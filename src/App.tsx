/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  DocumentType,
  CoCSection,
  DEFAULT_ENFORCEMENT_SETTINGS,
  EnforcementSettings,
  buildEnforcementMarkdown,
  COC_TEMPLATES,
  CONTACT_TEMPLATES,
  SECURITY_TEMPLATES,
  CODEOWNERS_TEMPLATES,
  PRESET_CUSTOM_SECTIONS,
} from './data/templates';

// Format timestamp as HHMMSSDDMMYYYY
function generate14DigitTimestamp(): string {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const mon = String(now.getMonth() + 1).padStart(2, '0');
  const yyyy = String(now.getFullYear());
  return `${hh}${mm}${ss}${dd}${mon}${yyyy}`;
}

// Convert 14-digit HHMMSSDDMMYYYY string into human-readable format
function parse14DigitTimestamp(ts: string): string {
  if (!ts || ts.length !== 14) return ts || 'N/A';
  const hh = ts.substring(0, 2);
  const mm = ts.substring(2, 4);
  const ss = ts.substring(4, 6);
  const dd = ts.substring(6, 8);
  const mon = ts.substring(8, 10);
  const yyyy = ts.substring(10, 14);
  return `${hh}:${mm}:${ss} on ${dd}/${mon}/${yyyy}`;
}

// Encode ASCII payload into Unicode Tag Characters (Plane 14)
function encodeStegoPayload(payload: string): string {
  let tagStr = '\u{E0001}';
  for (let i = 0; i < payload.length; i++) {
    tagStr += String.fromCodePoint(0xE0000 + payload.charCodeAt(i));
  }
  return tagStr;
}

// Extract and decode Unicode Tag sequence back to string payload
function decodeStegoPayload(text: string): string {
  const codePoints = Array.from(text).map((ch) => ch.codePointAt(0) || 0);
  let payload = '';
  for (const cp of codePoints) {
    if (cp >= 0xE0020 && cp <= 0xE007F) {
      payload += String.fromCharCode(cp - 0xE0000);
    }
  }
  return payload;
}

const INVISIBLE_MAGIC_HEADER = encodeStegoPayload('COC_HDR');

// Clean Markdown-to-HTML renderer
function renderMarkdownToHTML(md: string): string {
  let html = md.replace(/^␂\s*/, '').replace(/\s*␃$/, '');

  // Escape raw HTML brackets
  html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Tables
  const lines = html.split('\n');
  let inTable = false;
  const processedLines: string[] = [];

  for (const line of lines) {
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      if (!inTable) {
        processedLines.push('<div class="overflow-x-auto my-3"><table class="w-full text-left border-collapse border border-slate-700 text-xs">');
        inTable = true;
      }
      if (line.includes('---')) {
        continue;
      }
      const cells = line
        .split('|')
        .slice(1, -1)
        .map((c) => c.trim());
      const rowHtml = cells.map((c) => `<td class="border border-slate-700 px-3 py-1.5">${c}</td>`).join('');
      processedLines.push(`<tr>${rowHtml}</tr>`);
    } else {
      if (inTable) {
        processedLines.push('</table></div>');
        inTable = false;
      }
      processedLines.push(line);
    }
  }
  if (inTable) processedLines.push('</table></div>');
  html = processedLines.join('\n');

  // Inline code
  html = html.replace(/`([^`]+)`/g, (_match, p1) => `<code>${p1}</code>`);

  // Headings
  html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

  // Bold & Italics
  html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');

  // Links
  html = html.replace(
    /\[(.*?)\]\((.*?)\)/gim,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
  );

  // Checkboxes and Bullet lists
  html = html.replace(/^- \[ \] (.*$)/gim, '<li>☐ $1</li>');
  html = html.replace(/^- \[x\] (.*$)/gim, '<li>☑ $1</li>');
  html = html.replace(/^- (.*$)/gim, '<li>$1</li>');

  const afterListLines = html.split('\n');
  let result = '';
  let inList = false;

  for (const line of afterListLines) {
    if (line.startsWith('<li>')) {
      if (!inList) {
        result += '<ul>';
        inList = true;
      }
      result += line;
    } else {
      if (inList) {
        result += '</ul>';
        inList = false;
      }
      if (
        line.trim().length > 0 &&
        !line.startsWith('<h') &&
        !line.startsWith('<code') &&
        !line.startsWith('<table') &&
        !line.startsWith('<tr>') &&
        !line.startsWith('<div') &&
        !line.startsWith('</div>')
      ) {
        result += `<p>${line}</p>`;
      } else {
        result += line;
      }
    }
  }
  if (inList) result += '</ul>';
  return result;
}

interface VerificationResult {
  valid: boolean;
  headerText: string;
  message?: string;
  fields?: Array<{ label: string; value: string }>;
}

type CoCTabKey = 'project' | 'enforcement' | 'sections';

interface CodeOwnerRule {
  id: string;
  pattern: string;
  owner: string;
}

export default function App() {
  // Document Type Selector: 'coc' | 'contact' | 'security' | 'codeowners'
  const [docType, setDocType] = useState<DocumentType>('coc');

  // Core Project Fields (Shared across documents, without Maintainers)
  const [projectName, setProjectName] = useState<string>(() => {
    return localStorage.getItem('vpl_project_name') || 'OpenCore Engine';
  });
  const [primaryContact, setPrimaryContact] = useState<string>(() => {
    return localStorage.getItem('vpl_primary_contact') || 'Alex Rivera (Community Lead)';
  });
  const [projectUrl, setProjectUrl] = useState<string>(() => {
    return localStorage.getItem('vpl_project_url') || 'https://github.com/opencore/engine';
  });
  const [year, setYear] = useState<string>(() => String(new Date().getFullYear()));

  // 1. CODE_OF_CONDUCT.md State
  const [cocTemplateId, setCocTemplateId] = useState<string>('standard');
  const [cocTab, setCocTab] = useState<CoCTabKey>('project');
  const [scopeChannels, setScopeChannels] = useState<string>(
    'GitHub Issues, Pull Requests, Discussions, and Community Discord'
  );
  const [enforcementSettings, setEnforcementSettings] = useState<EnforcementSettings>(
    () => DEFAULT_ENFORCEMENT_SETTINGS
  );
  const [cocSections, setCocSections] = useState<CoCSection[]>(() => {
    const defaultTemplate = COC_TEMPLATES[0];
    return defaultTemplate.sections.map((sec) => ({ ...sec }));
  });
  const [editingSectionId, setEditingSectionId] = useState<string | null>(null);

  // 2. CONTACT.md State
  const [contactTemplateId, setContactTemplateId] = useState<string>('standard-contact');
  const [primaryEmail, setPrimaryEmail] = useState<string>('alex@opencore.dev');
  const [conductEmail, setConductEmail] = useState<string>('conduct@opencore.dev');
  const [securityEmail, setSecurityEmail] = useState<string>('security@opencore.dev');
  const [communityChat, setCommunityChat] = useState<string>('[Discord Community Server](https://discord.gg/opencore)');
  const [responseSla, setResponseSla] = useState<string>('48 hours');

  // 3. SECURITY.md State
  const [securityTemplateId, setSecurityTemplateId] = useState<string>('standard-security');
  const [assessmentWindow, setAssessmentWindow] = useState<string>('7 calendar days');

  // 4. CODEOWNERS State
  const [codeownersTemplateId, setCodeownersTemplateId] = useState<string>('standard-codeowners');
  const [globalOwner, setGlobalOwner] = useState<string>('@opencore/maintainers');
  const [securityOwner, setSecurityOwner] = useState<string>('@opencore/security');
  const [docsOwner, setDocsOwner] = useState<string>('@opencore/docs');
  const [customRules, setCustomRules] = useState<CodeOwnerRule[]>([
    { id: '1', pattern: '/src/api/', owner: '@opencore/backend' },
    { id: '2', pattern: '/src/ui/', owner: '@opencore/frontend' },
  ]);

  // Options
  const [includeStegoTag, setIncludeStegoTag] = useState<boolean>(true);
  const [includeDelimiters, setIncludeDelimiters] = useState<boolean>(true);

  // Runtime Steganography Signature State
  const [signatureMeta, setSignatureMeta] = useState<{ uuid: string; timestamp: string }>(() => ({
    uuid: crypto.randomUUID(),
    timestamp: generate14DigitTimestamp(),
  }));

  const refreshSignature = useCallback(() => {
    setSignatureMeta({
      uuid: crypto.randomUUID(),
      timestamp: generate14DigitTimestamp(),
    });
  }, []);

  // View Mode: 'raw' | 'rendered'
  const [viewMode, setViewMode] = useState<'raw' | 'rendered'>('raw');

  // Feedback States
  const [downloadStatus, setDownloadStatus] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);

  // Inspector Modal State
  const [isInspectorOpen, setIsInspectorOpen] = useState<boolean>(false);
  const [inspectInput, setInspectInput] = useState<string>('');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);

  // Dynamic Enforcement Markdown for CoC
  const dynamicEnforcementMarkdown = useMemo(() => {
    return buildEnforcementMarkdown(enforcementSettings, projectName, primaryContact);
  }, [enforcementSettings, projectName, primaryContact]);

  // Determine current active filename
  const currentFilename = useMemo(() => {
    switch (docType) {
      case 'coc':
        return 'CODE_OF_CONDUCT.md';
      case 'contact':
        return 'CONTACT.md';
      case 'security':
        return 'SECURITY.md';
      case 'codeowners':
        return 'CODEOWNERS';
    }
  }, [docType]);

  // Compute final markdown output for each active document
  const { fullOutput, rawMarkdownForRender } = useMemo(() => {
    const safeYear = year.trim() || String(new Date().getFullYear());
    const safePrimaryContact = primaryContact.trim() || '[PRIMARY CONTACT]';
    const safeProjectName = projectName.trim() || '[PROJECT NAME]';
    const safeProjectUrl = projectUrl.trim() || '[PROJECT URL]';
    const safeScope = scopeChannels.trim() || 'project repositories and community spaces';

    const stegoPayloadStr = `VPL|${signatureMeta.uuid}|${signatureMeta.timestamp}|${safeProjectName}|${safeYear}|${currentFilename}`;
    const invisibleTag = includeStegoTag ? encodeStegoPayload(stegoPayloadStr) : '';

    let docBody = '';

    if (docType === 'coc') {
      const headerText = `# ${safeProjectName} Code of Conduct\n**Open Source Contributor Charter**\n*Stewardship: ${safePrimaryContact} (${safeYear})*{STEGO_TAG}\n\n`;
      const sectionBodies = cocSections.map((sec) => {
        let secTitle = sec.title;
        if (!secTitle.startsWith('#')) {
          secTitle = `## ${secTitle}`;
        }
        const secContent = sec.isEnforcement ? dynamicEnforcementMarkdown : sec.content;
        return `${secTitle}\n\n${secContent}`;
      });
      docBody = `${headerText}${sectionBodies.join('\n\n')}`;
    } else if (docType === 'contact') {
      const template = CONTACT_TEMPLATES.find((t) => t.id === contactTemplateId) || CONTACT_TEMPLATES[0];
      docBody = template.content;
    } else if (docType === 'security') {
      const template = SECURITY_TEMPLATES.find((t) => t.id === securityTemplateId) || SECURITY_TEMPLATES[0];
      docBody = template.content;
    } else if (docType === 'codeowners') {
      const template = CODEOWNERS_TEMPLATES.find((t) => t.id === codeownersTemplateId) || CODEOWNERS_TEMPLATES[0];
      let base = template.content;
      if (customRules.length > 0) {
        const customRows = customRules.map((r) => `${r.pattern} ${r.owner}`).join('\n');
        base += `\n# Custom Component Rules\n${customRows}\n`;
      }
      docBody = base;
    }

    // Interpolate universal placeholders
    docBody = docBody
      .replace(/\{PROJECT_NAME\}/g, safeProjectName)
      .replace(/\{PROJECT_URL\}/g, safeProjectUrl)
      .replace(/\{PRIMARY_CONTACT\}/g, safePrimaryContact)
      .replace(/\{PRIMARY_EMAIL\}/g, primaryEmail)
      .replace(/\{CONDUCT_EMAIL\}/g, conductEmail)
      .replace(/\{SECURITY_EMAIL\}/g, securityEmail)
      .replace(/\{COMMUNITY_CHAT\}/g, communityChat)
      .replace(/\{RESPONSE_SLA\}/g, responseSla)
      .replace(/\{ASSESSMENT_WINDOW\}/g, assessmentWindow)
      .replace(/\{GLOBAL_OWNER\}/g, globalOwner)
      .replace(/\{SECURITY_OWNER\}/g, securityOwner)
      .replace(/\{PRIMARY_OWNER\}/g, globalOwner)
      .replace(/\{DOCS_OWNER\}/g, docsOwner)
      .replace(/\{YEAR\}/g, safeYear)
      .replace(/\{SCOPE_CHANNELS\}/g, safeScope)
      .replace(/\{STEGO_TAG\}/g, invisibleTag);

    if (includeDelimiters && docType !== 'codeowners') {
      docBody = `␂ ${docBody} ␃`;
    }

    const prefix = includeStegoTag ? INVISIBLE_MAGIC_HEADER : '';

    return {
      fullOutput: prefix + docBody,
      rawMarkdownForRender: docBody,
    };
  }, [
    docType,
    year,
    primaryContact,
    projectName,
    projectUrl,
    scopeChannels,
    cocSections,
    dynamicEnforcementMarkdown,
    contactTemplateId,
    primaryEmail,
    conductEmail,
    securityEmail,
    communityChat,
    responseSla,
    securityTemplateId,
    assessmentWindow,
    codeownersTemplateId,
    globalOwner,
    securityOwner,
    docsOwner,
    customRules,
    signatureMeta,
    currentFilename,
    includeStegoTag,
    includeDelimiters,
  ]);

  const renderedHtml = useMemo(
    () => renderMarkdownToHTML(rawMarkdownForRender),
    [rawMarkdownForRender]
  );

  // Switch CoC Template
  const handleCoCTemplateChange = (tmplId: string) => {
    setCocTemplateId(tmplId);
    const tmpl = COC_TEMPLATES.find((t) => t.id === tmplId) || COC_TEMPLATES[0];
    setCocSections(tmpl.sections.map((s) => ({ ...s })));
    setEditingSectionId(null);
    refreshSignature();
  };

  // CoC Section Reorder
  const handleMoveSection = (index: number, direction: 'up' | 'down') => {
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= cocSections.length) return;
    const newSecs = [...cocSections];
    const [moved] = newSecs.splice(index, 1);
    newSecs.splice(targetIndex, 0, moved);
    setCocSections(newSecs);
    refreshSignature();
  };

  // CoC Section Delete
  const handleDeleteSection = (index: number) => {
    if (cocSections.length <= 1) {
      alert('Document must contain at least one section.');
      return;
    }
    setCocSections(cocSections.filter((_, idx) => idx !== index));
    refreshSignature();
  };

  // CoC Section Edit
  const handleUpdateSection = (id: string, newTitle: string, newContent: string) => {
    setCocSections((prev) =>
      prev.map((s) => (s.id === id ? { ...s, title: newTitle, content: newContent } : s))
    );
    refreshSignature();
  };

  // Add Custom Section to CoC
  const handleAddPresetSection = (preset: { title: string; content: string }) => {
    const newSec: CoCSection = {
      id: `custom-${Date.now()}`,
      title: `${cocSections.length + 1}. ${preset.title}`,
      content: preset.content,
      isCustom: true,
    };
    setCocSections((prev) => [...prev, newSec]);
    setEditingSectionId(newSec.id);
    refreshSignature();
  };

  // Download
  const handleDownload = () => {
    const blob = new Blob([fullOutput], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', currentFilename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadStatus(`Saved ${currentFilename}!`);
    setTimeout(() => setDownloadStatus(null), 2000);
  };

  // Copy
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(fullOutput);
      setCopyStatus('Copied!');
      setTimeout(() => setCopyStatus(null), 2000);
    } catch {
      setCopyStatus('Failed to copy');
      setTimeout(() => setCopyStatus(null), 2000);
    }
  };

  // Inspector logic
  const runVerification = useCallback((textToInspect: string) => {
    if (!textToInspect.trim()) {
      setVerificationResult({
        valid: false,
        headerText: 'Empty Input',
        message: 'Please paste document text or drop a file.',
      });
      return;
    }

    const headSnippet = textToInspect.substring(0, 180);
    const headDecoded = decodeStegoPayload(headSnippet);

    const isTagged = headDecoded.includes('COC_HDR') || headDecoded.includes('VPL_HDR');

    if (!isTagged) {
      setVerificationResult({
        valid: false,
        headerText: 'No Verification Tag Detected',
        message: 'This document does not contain an authentic hidden magic header tag.',
      });
      return;
    }

    const decodedStr = decodeStegoPayload(textToInspect);
    if (decodedStr.includes('VPL|')) {
      const parts = decodedStr.substring(decodedStr.indexOf('VPL|')).split('|');
      setVerificationResult({
        valid: true,
        headerText: 'Authentic Project Document Tag Detected!',
        fields: [
          { label: 'UUID Serial:', value: parts[1] || 'N/A' },
          { label: 'Minted Time:', value: parse14DigitTimestamp(parts[2] || '') },
          { label: 'Project Name:', value: parts[3] || 'N/A' },
          { label: 'Document Year:', value: parts[4] || 'N/A' },
          { label: 'Target File:', value: parts[5] || 'N/A' },
        ],
      });
      return;
    }

    setVerificationResult({
      valid: false,
      headerText: 'Malformed Document Tags',
      message: 'Magic header found, but payload data was corrupted.',
    });
  }, []);

  const handleDrop = (e: React.DragEvent<HTMLTextAreaElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      const file = files[0];
      const reader = new FileReader();
      reader.onload = (evt) => {
        const content = String(evt.target?.result || '');
        setInspectInput(content);
        runVerification(content);
      };
      reader.readAsText(file);
    }
  };

  return (
    <div className="min-h-screen flex flex-col p-4 md:p-6 bg-[#0f172a] text-[#f8fafc]">
      {/* Main 2-Column VPL Studio Grid */}
      <main className="max-w-[1440px] w-full mx-auto grid grid-cols-1 lg:grid-cols-[440px_1fr] gap-6 flex-1 items-stretch">
        {/* LEFT COLUMN: Controls & Document Customization */}
        <section className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 md:p-6 flex flex-col gap-4">
          {/* Brand Header */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <svg className="w-[38px] h-[38px] shrink-0" viewBox="0 0 100 100" aria-hidden="true">
                <rect width="100" height="100" rx="24" fill="#0f172a" />
                <rect
                  x="30"
                  y="18"
                  width="50"
                  height="64"
                  rx="6"
                  fill="#1e293b"
                  stroke="#11FFAA"
                  strokeWidth="5"
                />
                <path
                  d="M20 24 C20 20.7 22.7 18 26 18 H32 V82 H26 C22.7 82 20 79.3 20 76 Z"
                  fill="#11FFAA"
                />
                <rect x="34" y="76" width="44" height="6" fill="#94a3b8" />
                <path
                  d="M44 34 H68 M44 44 H68 M44 54 H60"
                  stroke="#11FFAA"
                  strokeWidth="4"
                  strokeLinecap="round"
                />
              </svg>
              <div>
                <h1 className="text-[1.3rem] font-bold text-[#f8fafc] leading-tight">
                  Open Source Suite
                </h1>
                <p className="text-[#94a3b8] text-[0.8rem]">
                  Community Governance File Generator
                </p>
              </div>
            </div>

            <a
              href="https://vpl.vopple.uk"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-semibold text-[#94a3b8] hover:text-[#11FFAA] transition-colors whitespace-nowrap shrink-0 underline underline-offset-4"
              title="Open VPL License Studio"
            >
              VPL Studio ↗
            </a>
          </div>

          {/* Document File Selector Tabs */}
          <div className="flex flex-col gap-1.5">
            <label className="vpl-label text-xs">Target File to Generate</label>
            <div className="grid grid-cols-2 sm:grid-cols-4 bg-[#0f172a] p-[3px] rounded-lg border border-[#334155] text-xs font-semibold">
              <button
                type="button"
                onClick={() => {
                  setDocType('coc');
                  refreshSignature();
                }}
                className={`py-1.5 px-2 rounded-md transition-all text-center cursor-pointer truncate ${
                  docType === 'coc'
                    ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                    : 'text-[#94a3b8] hover:text-[#f8fafc]'
                }`}
              >
                CoC
              </button>
              <button
                type="button"
                onClick={() => {
                  setDocType('contact');
                  refreshSignature();
                }}
                className={`py-1.5 px-2 rounded-md transition-all text-center cursor-pointer truncate ${
                  docType === 'contact'
                    ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                    : 'text-[#94a3b8] hover:text-[#f8fafc]'
                }`}
              >
                CONTACT
              </button>
              <button
                type="button"
                onClick={() => {
                  setDocType('security');
                  refreshSignature();
                }}
                className={`py-1.5 px-2 rounded-md transition-all text-center cursor-pointer truncate ${
                  docType === 'security'
                    ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                    : 'text-[#94a3b8] hover:text-[#f8fafc]'
                }`}
              >
                SECURITY
              </button>
              <button
                type="button"
                onClick={() => {
                  setDocType('codeowners');
                  refreshSignature();
                }}
                className={`py-1.5 px-2 rounded-md transition-all text-center cursor-pointer truncate ${
                  docType === 'codeowners'
                    ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                    : 'text-[#94a3b8] hover:text-[#f8fafc]'
                }`}
              >
                CODEOWNERS
              </button>
            </div>
          </div>

          {/* Shared Project Fields */}
          <div className="p-3 rounded-lg bg-[#0f172a] border border-[#334155] flex flex-col gap-2.5">
            <span className="vpl-label text-[0.72rem] text-[#11FFAA]">
              Project Essentials
            </span>
            <div className="grid grid-cols-[1fr_100px] gap-2">
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-[0.68rem]">Project Name</label>
                <input
                  type="text"
                  value={projectName}
                  onChange={(e) => {
                    setProjectName(e.target.value);
                    localStorage.setItem('vpl_project_name', e.target.value);
                    refreshSignature();
                  }}
                  className="vpl-input text-xs py-1.5"
                  placeholder="e.g., RocketEngine"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-[0.68rem]">Year</label>
                <input
                  type="text"
                  value={year}
                  onChange={(e) => {
                    setYear(e.target.value);
                    refreshSignature();
                  }}
                  className="vpl-input text-xs py-1.5 font-mono tabular-nums"
                  placeholder="2026"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <label className="vpl-label text-[0.68rem]">Primary Contact Person</label>
              <input
                type="text"
                value={primaryContact}
                onChange={(e) => {
                  setPrimaryContact(e.target.value);
                  localStorage.setItem('vpl_primary_contact', e.target.value);
                  refreshSignature();
                }}
                className="vpl-input text-xs py-1.5"
                placeholder="e.g., Alex Vance (Community Lead)"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="vpl-label text-[0.68rem]">Repository / Project URL</label>
              <input
                type="text"
                value={projectUrl}
                onChange={(e) => {
                  setProjectUrl(e.target.value);
                  localStorage.setItem('vpl_project_url', e.target.value);
                  refreshSignature();
                }}
                className="vpl-input text-xs py-1.5"
                placeholder="https://github.com/org/rocketengine"
              />
            </div>
          </div>

          {/* DOCUMENT-SPECIFIC PANELS */}

          {/* 1. CODE OF CONDUCT PANEL */}
          {docType === 'coc' && (
            <div className="flex flex-col gap-3">
              {/* Template Standard Selector with clean non-janky names */}
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-xs">Template Standard</label>
                <select
                  value={cocTemplateId}
                  onChange={(e) => handleCoCTemplateChange(e.target.value)}
                  className="vpl-input text-xs py-1.5 cursor-pointer"
                >
                  {COC_TEMPLATES.map((tmpl) => (
                    <option key={tmpl.id} value={tmpl.id}>
                      {tmpl.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* 3 CoC Sub-Tabs */}
              <div className="grid grid-cols-3 bg-[#0f172a] p-[3px] rounded-lg border border-[#334155] text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setCocTab('project')}
                  className={`py-1 px-1 rounded transition-all text-center cursor-pointer truncate ${
                    cocTab === 'project'
                      ? 'bg-[#1e293b] text-[#11FFAA]'
                      : 'text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  Scope
                </button>
                <button
                  type="button"
                  onClick={() => setCocTab('enforcement')}
                  className={`py-1 px-1 rounded transition-all text-center cursor-pointer truncate ${
                    cocTab === 'enforcement'
                      ? 'bg-[#1e293b] text-[#11FFAA]'
                      : 'text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  Enforcement
                </button>
                <button
                  type="button"
                  onClick={() => setCocTab('sections')}
                  className={`py-1 px-1 rounded transition-all text-center cursor-pointer truncate ${
                    cocTab === 'sections'
                      ? 'bg-[#1e293b] text-[#11FFAA]'
                      : 'text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  Sections ({cocSections.length})
                </button>
              </div>

              {cocTab === 'project' && (
                <div className="flex flex-col gap-2">
                  <div className="flex flex-col gap-1">
                    <label className="vpl-label text-xs">Community Scope &amp; Channels</label>
                    <input
                      type="text"
                      value={scopeChannels}
                      onChange={(e) => {
                        setScopeChannels(e.target.value);
                        refreshSignature();
                      }}
                      className="vpl-input text-xs py-1.5"
                      placeholder="GitHub Issues, PRs, Discussions, Discord"
                    />
                  </div>
                  <p className="text-[0.72rem] text-[#94a3b8] leading-relaxed">
                    Note: Specific email addresses and communication channels are linked directly to{' '}
                    <code className="text-[#11FFAA]">CONTACT.md</code> to keep your Code of Conduct clean and maintainable.
                  </p>
                </div>
              )}

              {cocTab === 'enforcement' && (
                <div className="flex flex-col gap-3 max-h-[360px] overflow-y-auto pr-1">
                  {/* Reporting */}
                  <div className="p-2.5 rounded bg-[#0f172a] border border-[#334155] flex flex-col gap-2 text-xs">
                    <span className="font-bold text-white text-[0.72rem] uppercase tracking-wide">
                      A. Reporting Channels
                    </span>
                    <div className="grid grid-cols-1 gap-1">
                      {[
                        'Confidential Email',
                        'Anonymous Web Form',
                        'Private Security Advisory',
                        'Direct Message to Primary Contact',
                      ].map((ch) => (
                        <label key={ch} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={enforcementSettings.reportingChannels.includes(ch)}
                            onChange={() => {
                              setEnforcementSettings((s) => {
                                const exists = s.reportingChannels.includes(ch);
                                return {
                                  ...s,
                                  reportingChannels: exists
                                    ? s.reportingChannels.filter((c) => c !== ch)
                                    : [...s.reportingChannels, ch],
                                };
                              });
                              refreshSignature();
                            }}
                            className="accent-[#11FFAA] w-3 h-3 rounded"
                          />
                          <span className="text-[#e2e8f0]">{ch}</span>
                        </label>
                      ))}
                    </div>

                    <div className="flex flex-col gap-1 pt-1">
                      <label className="vpl-label text-[0.68rem]">Response SLA</label>
                      <select
                        value={enforcementSettings.slaWindow}
                        onChange={(e) => {
                          setEnforcementSettings((s) => ({ ...s, slaWindow: e.target.value }));
                          refreshSignature();
                        }}
                        className="vpl-input text-xs py-1 cursor-pointer"
                      >
                        <option value="24 hours">24 hours</option>
                        <option value="48 hours">48 hours (Standard)</option>
                        <option value="72 hours">72 hours</option>
                        <option value="5 business days">5 business days</option>
                      </select>
                    </div>
                  </div>

                  {/* Who Handles */}
                  <div className="p-2.5 rounded bg-[#0f172a] border border-[#334155] flex flex-col gap-2 text-xs">
                    <span className="font-bold text-white text-[0.72rem] uppercase tracking-wide">
                      B. Review Body
                    </span>
                    <select
                      value={enforcementSettings.handlingBodyType}
                      onChange={(e) => {
                        setEnforcementSettings((s) => ({
                          ...s,
                          handlingBodyType: e.target.value as EnforcementSettings['handlingBodyType'],
                        }));
                        refreshSignature();
                      }}
                      className="vpl-input text-xs py-1 cursor-pointer"
                    >
                      <option value="individual">
                        Designated Primary Contact ({primaryContact || 'Primary Contact'})
                      </option>
                      <option value="committee">Conduct Review Committee / Working Group</option>
                      <option value="external">Independent Third-Party Arbiter</option>
                    </select>

                    <label className="flex items-center gap-2 cursor-pointer pt-1">
                      <input
                        type="checkbox"
                        checked={enforcementSettings.enableRecusalClause}
                        onChange={(e) => {
                          setEnforcementSettings((s) => ({ ...s, enableRecusalClause: e.target.checked }));
                          refreshSignature();
                        }}
                        className="accent-[#11FFAA] w-3 h-3 rounded"
                      />
                      <span className="text-[#e2e8f0]">Conflict of Interest &amp; Recusal Clause</span>
                    </label>
                  </div>

                  {/* Consequences */}
                  <div className="p-2.5 rounded bg-[#0f172a] border border-[#334155] flex flex-col gap-1.5 text-xs">
                    <span className="font-bold text-white text-[0.72rem] uppercase tracking-wide">
                      C. Consequences Ladder
                    </span>
                    <div className="flex flex-col gap-1 text-[0.75rem] text-[#94a3b8]">
                      <div>✓ Level 1: Correction &amp; Private Warning</div>
                      <div>✓ Level 2: Formal Warning &amp; Interaction Limits</div>
                      <div className="flex items-center justify-between">
                        <span>✓ Level 3: Temporary Suspension</span>
                        <select
                          value={enforcementSettings.consequenceLevels.temporaryBan.duration}
                          onChange={(e) => {
                            setEnforcementSettings((s) => ({
                              ...s,
                              consequenceLevels: {
                                ...s.consequenceLevels,
                                temporaryBan: {
                                  ...s.consequenceLevels.temporaryBan,
                                  duration: e.target.value,
                                },
                              },
                            }));
                            refreshSignature();
                          }}
                          className="bg-[#1e293b] border border-[#334155] rounded px-1 py-0.5 text-white text-[0.7rem]"
                        >
                          <option value="7 days">7 days</option>
                          <option value="14 days">14 days</option>
                          <option value="30 days">30 days</option>
                          <option value="90 days">90 days</option>
                        </select>
                      </div>
                      <div>✓ Level 4: Permanent Ban</div>
                    </div>
                  </div>
                </div>
              )}

              {cocTab === 'sections' && (
                <div className="flex flex-col gap-2 max-h-[360px] overflow-y-auto pr-1">
                  {cocSections.map((sec, index) => {
                    const isEditing = editingSectionId === sec.id;
                    return (
                      <div
                        key={sec.id}
                        className="p-2.5 rounded bg-[#0f172a] border border-[#334155] flex flex-col gap-1.5"
                      >
                        <div className="flex items-center justify-between gap-1">
                          <div className="flex items-center gap-1.5 truncate">
                            <span className="font-mono text-[0.7rem] text-[#11FFAA] font-bold">
                              § {index + 1}
                            </span>
                            <span className="text-xs font-semibold text-[#f8fafc] truncate">
                              {sec.title}
                            </span>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            <button
                              type="button"
                              disabled={index === 0}
                              onClick={() => handleMoveSection(index, 'up')}
                              className="px-1 py-0.5 rounded bg-[#1e293b] text-[#94a3b8] hover:text-white disabled:opacity-30 cursor-pointer text-[0.7rem]"
                            >
                              ▲
                            </button>
                            <button
                              type="button"
                              disabled={index === cocSections.length - 1}
                              onClick={() => handleMoveSection(index, 'down')}
                              className="px-1 py-0.5 rounded bg-[#1e293b] text-[#94a3b8] hover:text-white disabled:opacity-30 cursor-pointer text-[0.7rem]"
                            >
                              ▼
                            </button>
                            <button
                              type="button"
                              onClick={() => setEditingSectionId(isEditing ? null : sec.id)}
                              className="px-1.5 py-0.5 rounded bg-[#1e293b] text-[#94a3b8] hover:text-white cursor-pointer text-[0.7rem]"
                            >
                              {isEditing ? 'Close' : 'Edit'}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteSection(index)}
                              className="px-1.5 py-0.5 rounded bg-[#1e293b] text-[#ef4444] hover:bg-[#ef4444] hover:text-white cursor-pointer text-[0.7rem]"
                            >
                              ✕
                            </button>
                          </div>
                        </div>

                        {sec.isEnforcement && (
                          <span className="text-[0.68rem] text-[#11FFAA]">
                            ⚡ Dynamic Enforcement Section
                          </span>
                        )}

                        {isEditing && (
                          <div className="flex flex-col gap-1.5 pt-1.5 border-t border-[#334155]">
                            <input
                              type="text"
                              value={sec.title}
                              onChange={(e) => handleUpdateSection(sec.id, e.target.value, sec.content)}
                              className="vpl-input text-xs py-1"
                            />
                            <textarea
                              rows={4}
                              value={sec.isEnforcement ? dynamicEnforcementMarkdown : sec.content}
                              onChange={(e) => handleUpdateSection(sec.id, sec.title, e.target.value)}
                              disabled={sec.isEnforcement}
                              className="vpl-textarea text-xs"
                            />
                          </div>
                        )}
                      </div>
                    );
                  })}

                  <div className="p-2 rounded bg-[#0f172a] border border-[#334155] flex flex-col gap-1.5 mt-1">
                    <span className="vpl-label text-[0.68rem] text-[#11FFAA]">+ Add Section</span>
                    <div className="grid grid-cols-1 gap-1">
                      {PRESET_CUSTOM_SECTIONS.map((p) => (
                        <button
                          key={p.title}
                          type="button"
                          onClick={() => handleAddPresetSection(p)}
                          className="text-left text-[0.72rem] p-1.5 rounded bg-[#1e293b] hover:bg-[#334155] text-[#e2e8f0] flex items-center justify-between cursor-pointer"
                        >
                          <span className="truncate">{p.title}</span>
                          <span className="text-[#11FFAA] font-bold ml-1">+</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 2. CONTACT.MD PANEL */}
          {docType === 'contact' && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-xs">Template Standard</label>
                <select
                  value={contactTemplateId}
                  onChange={(e) => {
                    setContactTemplateId(e.target.value);
                    refreshSignature();
                  }}
                  className="vpl-input text-xs py-1.5 cursor-pointer"
                >
                  {CONTACT_TEMPLATES.map((tmpl) => (
                    <option key={tmpl.id} value={tmpl.id}>
                      {tmpl.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-col gap-2.5">
                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Primary Contact Email</label>
                  <input
                    type="text"
                    value={primaryEmail}
                    onChange={(e) => {
                      setPrimaryEmail(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="alex@opencore.dev"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Conduct Reports Email</label>
                  <input
                    type="text"
                    value={conductEmail}
                    onChange={(e) => {
                      setConductEmail(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="conduct@opencore.dev"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Security Contact Email</label>
                  <input
                    type="text"
                    value={securityEmail}
                    onChange={(e) => {
                      setSecurityEmail(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="security@opencore.dev"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Community Chat / Discord Link</label>
                  <input
                    type="text"
                    value={communityChat}
                    onChange={(e) => {
                      setCommunityChat(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="[Discord Server](https://discord.gg/opencore)"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Response SLA</label>
                  <select
                    value={responseSla}
                    onChange={(e) => {
                      setResponseSla(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5 cursor-pointer"
                  >
                    <option value="24 hours">24 hours</option>
                    <option value="48 hours">48 hours (Standard)</option>
                    <option value="72 hours">72 hours</option>
                    <option value="5 business days">5 business days</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* 3. SECURITY.MD PANEL */}
          {docType === 'security' && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-xs">Template Standard</label>
                <select
                  value={securityTemplateId}
                  onChange={(e) => {
                    setSecurityTemplateId(e.target.value);
                    refreshSignature();
                  }}
                  className="vpl-input text-xs py-1.5 cursor-pointer"
                >
                  {SECURITY_TEMPLATES.map((tmpl) => (
                    <option key={tmpl.id} value={tmpl.id}>
                      {tmpl.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-col gap-2.5">
                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Security Contact Email</label>
                  <input
                    type="text"
                    value={securityEmail}
                    onChange={(e) => {
                      setSecurityEmail(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="security@opencore.dev"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Initial Response SLA</label>
                  <select
                    value={responseSla}
                    onChange={(e) => {
                      setResponseSla(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5 cursor-pointer"
                  >
                    <option value="24 hours">24 hours</option>
                    <option value="48 hours">48 hours (Standard)</option>
                    <option value="72 hours">72 hours</option>
                  </select>
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Triage &amp; Assessment Window</label>
                  <input
                    type="text"
                    value={assessmentWindow}
                    onChange={(e) => {
                      setAssessmentWindow(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5"
                    placeholder="7 calendar days"
                  />
                </div>
              </div>
            </div>
          )}

          {/* 4. CODEOWNERS PANEL */}
          {docType === 'codeowners' && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label className="vpl-label text-xs">Template Standard</label>
                <select
                  value={codeownersTemplateId}
                  onChange={(e) => {
                    setCodeownersTemplateId(e.target.value);
                    refreshSignature();
                  }}
                  className="vpl-input text-xs py-1.5 cursor-pointer"
                >
                  {CODEOWNERS_TEMPLATES.map((tmpl) => (
                    <option key={tmpl.id} value={tmpl.id}>
                      {tmpl.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex flex-col gap-2.5">
                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Global Default Owner</label>
                  <input
                    type="text"
                    value={globalOwner}
                    onChange={(e) => {
                      setGlobalOwner(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5 font-mono"
                    placeholder="@org/maintainers"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Security Policy Owner</label>
                  <input
                    type="text"
                    value={securityOwner}
                    onChange={(e) => {
                      setSecurityOwner(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5 font-mono"
                    placeholder="@org/security"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="vpl-label text-xs">Documentation Owner</label>
                  <input
                    type="text"
                    value={docsOwner}
                    onChange={(e) => {
                      setDocsOwner(e.target.value);
                      refreshSignature();
                    }}
                    className="vpl-input text-xs py-1.5 font-mono"
                    placeholder="@org/docs"
                  />
                </div>

                {/* Additional Rule Rows */}
                <div className="flex flex-col gap-1.5 pt-1">
                  <div className="flex items-center justify-between">
                    <span className="vpl-label text-[0.68rem]">Custom Path Rules</span>
                    <button
                      type="button"
                      onClick={() => {
                        setCustomRules((prev) => [
                          ...prev,
                          { id: String(Date.now()), pattern: '/path/', owner: '@team' },
                        ]);
                        refreshSignature();
                      }}
                      className="text-[0.7rem] text-[#11FFAA] font-semibold hover:underline cursor-pointer"
                    >
                      + Add Rule
                    </button>
                  </div>
                  {customRules.map((rule, idx) => (
                    <div key={rule.id} className="grid grid-cols-[1fr_1fr_24px] gap-1 items-center">
                      <input
                        type="text"
                        value={rule.pattern}
                        onChange={(e) => {
                          const val = e.target.value;
                          setCustomRules((prev) =>
                            prev.map((r, i) => (i === idx ? { ...r, pattern: val } : r))
                          );
                          refreshSignature();
                        }}
                        className="vpl-input text-xs py-1 font-mono"
                        placeholder="/path/"
                      />
                      <input
                        type="text"
                        value={rule.owner}
                        onChange={(e) => {
                          const val = e.target.value;
                          setCustomRules((prev) =>
                            prev.map((r, i) => (i === idx ? { ...r, owner: val } : r))
                          );
                          refreshSignature();
                        }}
                        className="vpl-input text-xs py-1 font-mono"
                        placeholder="@owner"
                      />
                      <button
                        type="button"
                        onClick={() => {
                          setCustomRules((prev) => prev.filter((_, i) => i !== idx));
                          refreshSignature();
                        }}
                        className="text-[#ef4444] hover:text-white text-xs cursor-pointer"
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Steganography & Delimiter Options */}
          <div className="flex items-center justify-between gap-4 pt-2 border-t border-[#334155] text-[0.76rem] text-[#94a3b8]">
            <label className="flex items-center gap-2 cursor-pointer select-none hover:text-[#f8fafc]">
              <input
                type="checkbox"
                checked={includeStegoTag}
                onChange={(e) => setIncludeStegoTag(e.target.checked)}
                className="accent-[#11FFAA] w-3.5 h-3.5 cursor-pointer"
              />
              <span>Plane-14 Verification Tag</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer select-none hover:text-[#f8fafc]">
              <input
                type="checkbox"
                checked={includeDelimiters}
                onChange={(e) => setIncludeDelimiters(e.target.checked)}
                className="accent-[#11FFAA] w-3.5 h-3.5 cursor-pointer"
              />
              <span>␂ / ␃ Delimiters</span>
            </label>
          </div>

          {/* Bottom Action Buttons */}
          <div className="flex flex-col gap-2 mt-auto pt-2">
            <button
              type="button"
              onClick={handleDownload}
              className="w-full py-2.5 px-4 rounded-md font-bold text-[0.88rem] cursor-pointer transition-all active:scale-[0.98] whitespace-nowrap"
              style={{
                backgroundColor: downloadStatus ? 'var(--success)' : 'var(--accent)',
                color: downloadStatus ? '#ffffff' : 'var(--accent-text)',
              }}
            >
              {downloadStatus || `Download ${currentFilename}`}
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="w-full py-2.5 px-4 rounded-md font-bold text-[0.88rem] cursor-pointer transition-all active:scale-[0.98] whitespace-nowrap"
              style={{
                backgroundColor: copyStatus ? 'var(--success)' : 'var(--secondary-btn)',
                color: copyStatus ? '#ffffff' : 'var(--text)',
              }}
            >
              {copyStatus || 'Copy File Content'}
            </button>
          </div>
        </section>

        {/* RIGHT COLUMN: Live Document Preview */}
        <section className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 md:p-6 flex flex-col gap-4">
          {/* Header Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-[1.2rem] font-bold text-[#f8fafc]">
                {currentFilename} Preview
              </h2>
              <div className="flex bg-[#0f172a] p-[3px] rounded-lg border border-[#334155]">
                <button
                  type="button"
                  onClick={() => setViewMode('raw')}
                  className={`px-3 py-1.5 text-[0.8rem] font-semibold rounded-md cursor-pointer transition-all whitespace-nowrap ${
                    viewMode === 'raw'
                      ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                      : 'text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  Raw Content
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('rendered')}
                  className={`px-3 py-1.5 text-[0.8rem] font-semibold rounded-md cursor-pointer transition-all whitespace-nowrap ${
                    viewMode === 'rendered'
                      ? 'bg-[#1e293b] text-[#11FFAA] shadow-sm'
                      : 'text-[#94a3b8] hover:text-[#f8fafc]'
                  }`}
                >
                  Processed View
                </button>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setIsInspectorOpen(true)}
              className="px-3.5 py-1.5 rounded-md font-bold text-[0.84rem] bg-[#3b82f6] hover:bg-[#2563eb] text-white cursor-pointer transition-all active:scale-[0.98] whitespace-nowrap"
            >
              Inspect &amp; Verify Document
            </button>
          </div>

          {/* Quick Info Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#334155] text-xs text-[#94a3b8]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-white font-semibold">{projectName}</span>
              <span>·</span>
              <span>Primary Contact: <strong className="text-[#11FFAA]">{primaryContact}</strong></span>
            </div>
            <div className="font-mono text-[0.75rem] text-[#94a3b8]">
              File: <span className="text-[#11FFAA]">{currentFilename}</span>
            </div>
          </div>

          {/* Raw Textarea or Rendered HTML */}
          {viewMode === 'raw' ? (
            <textarea
              id="docOutput"
              readOnly
              value={fullOutput}
              aria-label="Generated File Content"
              className="w-full flex-1 min-h-[540px] bg-[#0f172a] border border-[#334155] rounded-lg text-[#e2e8f0] font-mono text-[0.86rem] p-5 resize-none leading-[1.65] focus:outline-none focus:border-[#11FFAA]"
            />
          ) : (
            <div
              id="renderedOutput"
              className="markdown-body"
              dangerouslySetInnerHTML={{ __html: renderedHtml }}
            />
          )}
        </section>
      </main>

      {/* VERIFICATION INSPECTOR MODAL */}
      {isInspectorOpen && (
        <div
          className="fixed inset-0 bg-[#0f172a]/85 backdrop-blur-xs flex items-center justify-center p-4 z-50"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsInspectorOpen(false);
          }}
        >
          <div className="bg-[#1e293b] border border-[#334155] rounded-xl max-w-[650px] w-full p-6 flex flex-col gap-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-[1.15rem] font-bold text-[#f8fafc]">
                Document Verification Inspector
              </h3>
              <button
                type="button"
                onClick={() => setIsInspectorOpen(false)}
                className="text-[#94a3b8] hover:text-[#f8fafc] text-2xl leading-none px-2 cursor-pointer"
                aria-label="Close Inspector Modal"
              >
                &times;
              </button>
            </div>

            <p className="text-[#94a3b8] text-[0.85rem] -mt-2">
              Paste generated document text or drag &amp; drop a file to decode hidden Plane-14 tags.
            </p>

            <textarea
              value={inspectInput}
              onChange={(e) => setInspectInput(e.target.value)}
              onDragEnter={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setIsDragging(true);
              }}
              onDragOver={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setIsDragging(true);
              }}
              onDragLeave={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setIsDragging(false);
              }}
              onDrop={handleDrop}
              placeholder="Paste document text or drag & drop a file here..."
              className={`h-[180px] w-full bg-[#0f172a] rounded-lg text-[#e2e8f0] font-mono text-[0.85rem] p-4 resize-y transition-all focus:outline-none ${
                isDragging
                  ? 'border-2 border-dashed border-[#11FFAA] shadow-[0_0_12px_rgba(17,255,170,0.4)]'
                  : 'border border-[#334155] focus:border-[#11FFAA]'
              }`}
            />

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => runVerification(inspectInput)}
                className="py-2.5 px-5 rounded-md font-bold text-[0.86rem] bg-[#11FFAA] hover:bg-[#00e699] text-[#0f172a] cursor-pointer transition-all active:scale-[0.98]"
              >
                Decode &amp; Verify Tags
              </button>
              <button
                type="button"
                onClick={() => {
                  setInspectInput(fullOutput);
                  runVerification(fullOutput);
                }}
                className="py-2.5 px-4 rounded-md font-semibold text-[0.84rem] bg-[#334155] hover:bg-[#475569] text-[#f8fafc] cursor-pointer transition-all active:scale-[0.98]"
              >
                Load Current Output to Test
              </button>
            </div>

            {verificationResult && (
              <div className="bg-[#0f172a] border border-[#334155] rounded-lg p-4 flex flex-col gap-2 text-[0.88rem]">
                <div
                  className={`font-bold text-[0.95rem] ${
                    verificationResult.valid ? 'text-[#22c55e]' : 'text-[#ef4444]'
                  }`}
                >
                  {verificationResult.headerText}
                </div>

                {verificationResult.message && (
                  <p className="text-[#94a3b8] text-[0.84rem]">{verificationResult.message}</p>
                )}

                {verificationResult.fields && (
                  <div className="grid grid-cols-[140px_1fr] gap-y-1.5 gap-x-3 mt-1">
                    {verificationResult.fields.map((field) => (
                      <React.Fragment key={field.label}>
                        <div className="text-[#94a3b8] font-semibold">{field.label}</div>
                        <div className="font-mono text-[#f8fafc] break-all tabular-nums">
                          {field.value}
                        </div>
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
