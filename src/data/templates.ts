export type DocumentType = 'coc' | 'contact' | 'security' | 'codeowners';

export interface CoCSection {
  id: string;
  title: string;
  content: string;
  isEnforcement?: boolean;
  isCustom?: boolean;
}

export interface CoCTemplate {
  id: string;
  name: string; // Clean, simple name (no janky version codes)
  summary: string;
  sections: CoCSection[];
}

export interface GenericTemplate {
  id: string;
  name: string;
  summary: string;
  content: string;
}

export interface EnforcementSettings {
  reportingChannels: string[];
  otherReportingChannel: string;
  requiredReportDetails: string[];
  slaWindow: string;
  handlingBodyType: 'individual' | 'team' | 'committee' | 'external';
  enableRecusalClause: boolean;
  enableAntiRetaliation: boolean;
  consequenceLevels: {
    correction: { enabled: boolean; title: string; impact: string; consequence: string };
    warning: { enabled: boolean; title: string; impact: string; consequence: string };
    temporaryBan: { enabled: boolean; title: string; duration: string; impact: string; consequence: string };
    permanentBan: { enabled: boolean; title: string; impact: string; consequence: string };
  };
  enableAppeals: boolean;
  appealProcess: string;
}

export const DEFAULT_ENFORCEMENT_SETTINGS: EnforcementSettings = {
  reportingChannels: ['Confidential Email', 'Private Security Advisory'],
  otherReportingChannel: '',
  requiredReportDetails: [
    'Date, time, and location/channel of the incident',
    'Account(s) or individual(s) involved',
    'Detailed description of what occurred',
    'Screenshots, links, or verifiable evidence'
  ],
  slaWindow: '48 hours',
  handlingBodyType: 'individual',
  enableRecusalClause: true,
  enableAntiRetaliation: true,
  consequenceLevels: {
    correction: {
      enabled: true,
      title: 'Level 1: Correction',
      impact: 'Use of inappropriate language or other behavior deemed unprofessional or unwelcome in the community.',
      consequence: 'A private, written notice providing clarity around the nature of the violation and an explanation of why the behavior was inappropriate. A public or private apology may be requested.'
    },
    warning: {
      enabled: true,
      title: 'Level 2: Formal Warning',
      impact: 'A violation through a single serious incident or a series of actions.',
      consequence: 'A warning with consequences for continued behavior. Interaction restrictions with affected community members, including a mandatory cooling-off period from discussions.'
    },
    temporaryBan: {
      enabled: true,
      title: 'Level 3: Temporary Suspension',
      impact: 'A serious violation of community standards, harassment, or sustained inappropriate behavior.',
      duration: '30 days',
      consequence: 'A temporary ban (30 days) from any sort of interaction or public communication within project spaces, issue triage, and repositories.'
    },
    permanentBan: {
      enabled: true,
      title: 'Level 4: Permanent Ban',
      impact: 'Demonstrating a pattern of violation, severe harassment, doxxing, or aggression toward individuals or classes of individuals.',
      consequence: 'A permanent ban from all project spaces, discussion forums, and community organization repositories.'
    }
  },
  enableAppeals: true,
  appealProcess: 'Decisions may be appealed within 14 days of notice by submitting a written appeal. Appeals are reviewed by a neutral community lead not involved in the original complaint.'
};

export function buildEnforcementMarkdown(
  settings: EnforcementSettings,
  projectName: string,
  primaryContact: string
): string {
  const channelsList = [...settings.reportingChannels];
  if (settings.otherReportingChannel.trim()) {
    channelsList.push(settings.otherReportingChannel.trim());
  }
  const channelsFormatted = channelsList.length > 0 ? channelsList.join(', ') : 'Confidential Email';

  const handlerDescription =
    settings.handlingBodyType === 'individual'
      ? `**${primaryContact || 'The primary contact person'}**`
      : settings.handlingBodyType === 'committee'
      ? `The **${projectName || 'Project'} Conduct Review Committee**`
      : settings.handlingBodyType === 'external'
      ? `An independent third-party ombudsperson appointed by **${projectName || 'Project'}**`
      : `The community governance team of **${projectName || 'Project'}**`;

  let md = `### How to Report Violations

If you experience, witness, or become aware of unacceptable behavior, please report it immediately:

- **Primary Contact Person:** ${primaryContact || 'Community Lead'}
- **Reporting Channels:** ${channelsFormatted}
- **Contact Details:** Refer to [CONTACT.md](CONTACT.md) for current private communication channels.
- **Initial Response SLA:** Within **${settings.slaWindow}**

When filing a report, please include as much of the following information as possible to expedite a fair review:
${settings.requiredReportDetails.map((item) => `- ${item}`).join('\n')}

### Who Handles Reports & Governance

All reports are investigated by ${handlerDescription}. Every reviewer is committed to confidentiality, neutrality, and the safety of the reporting party.`;

  if (settings.enableRecusalClause) {
    md += `\n\n- **Conflict of Interest & Recusal:** If a report involves or names any member of the review body, that individual is immediately recused from receiving report details, investigating, or participating in resolution decisions.`;
  }

  if (settings.enableAntiRetaliation) {
    md += `\n\n- **Anti-Retaliation Protection:** **${projectName || 'Project'}** strictly prohibits retaliation of any kind against anyone who reports a violation in good faith or participates in an investigation.`;
  }

  md += `\n\n### Potential Consequences & Enforcement Ladder

The review team will follow these guidelines when determining appropriate, proportional consequences:`;

  const levels = settings.consequenceLevels;
  if (levels.correction.enabled) {
    md += `\n\n#### ${levels.correction.title}
- **Community Impact:** ${levels.correction.impact}
- **Consequence:** ${levels.correction.consequence}`;
  }

  if (levels.warning.enabled) {
    md += `\n\n#### ${levels.warning.title}
- **Community Impact:** ${levels.warning.impact}
- **Consequence:** ${levels.warning.consequence}`;
  }

  if (levels.temporaryBan.enabled) {
    md += `\n\n#### ${levels.temporaryBan.title} (${levels.temporaryBan.duration})
- **Community Impact:** ${levels.temporaryBan.impact}
- **Consequence:** ${levels.temporaryBan.consequence}`;
  }

  if (levels.permanentBan.enabled) {
    md += `\n\n#### ${levels.permanentBan.title}
- **Community Impact:** ${levels.permanentBan.impact}
- **Consequence:** ${levels.permanentBan.consequence}`;
  }

  if (settings.enableAppeals && settings.appealProcess) {
    md += `\n\n### Appeals Process\n\n${settings.appealProcess}`;
  }

  return md;
}

// 1. CODE_OF_CONDUCT.md Templates — Clean, non-janky names
export const COC_TEMPLATES: CoCTemplate[] = [
  {
    id: 'standard',
    name: 'Standard',
    summary: 'Comprehensive, balanced open-source code of conduct with clear positive standards and structured enforcement.',
    sections: [
      {
        id: 'pledge',
        title: '1. Our Pledge',
        content: `We as members and contributors of **{PROJECT_NAME}** pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, caste, color, religion, or sexual identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming, diverse, inclusive, and healthy community around [{PROJECT_NAME}]({PROJECT_URL}).`
      },
      {
        id: 'standards',
        title: '2. Our Standards',
        content: `Examples of behavior that contributes to a positive environment for our community include:

- **Demonstrating empathy and kindness** toward other contributors and users;
- **Being respectful** of differing technical opinions, viewpoints, and experiences;
- **Giving and gracefully accepting** constructive code review and architectural feedback;
- **Accepting responsibility** and apologizing to those affected by our mistakes, and learning from the experience;
- **Focusing on what is best** for the overall **{PROJECT_NAME}** community.

Examples of unacceptable behavior include:

- The use of sexualized language or imagery, and sexual attention or advances of any kind;
- Trolling, insulting or derogatory comments, and personal attacks in issues, commits, or pull requests;
- Public or private harassment of any community member;
- Publishing others' private information, such as a physical or email address, without their explicit permission ("doxxing");
- Deliberate disruption of technical discussions, issue triage, or release workflows;
- Other conduct which could reasonably be considered inappropriate in a collaborative open-source setting.`
      },
      {
        id: 'scope',
        title: '3. Scope & Spaces',
        content: `This Code of Conduct applies within all project spaces, including **{SCOPE_CHANNELS}**, and also applies when an individual is officially representing **{PROJECT_NAME}** or its community in public spaces.`
      },
      {
        id: 'enforcement',
        title: '4. Enforcement Guidelines & Violation Reporting',
        isEnforcement: true,
        content: ''
      },
      {
        id: 'attribution',
        title: '5. Attribution',
        content: `This Code of Conduct is adapted from the Contributor Covenant and formatted for **{PROJECT_NAME}**. Specific contact details are maintained in [CONTACT.md](CONTACT.md).`
      }
    ]
  },
  {
    id: 'minimalist',
    name: 'Minimalist',
    summary: 'Concise, direct 3-pillar pledge ideal for solo projects, micro-libraries, and lean utilities.',
    sections: [
      {
        id: 'philosophy',
        title: '1. Core Collaboration Principles',
        content: `**{PROJECT_NAME}** is dedicated to providing a welcoming, respectful, and constructive environment for every contributor and user.

When participating in **{SCOPE_CHANNELS}**, please adhere to three core principles:

- **Be human and respectful:** Treat fellow contributors with patience. Behind every pull request, bug report, and review is a person volunteering their time and focus.
- **Critique code, never people:** Keep technical disagreements focused strictly on architecture, performance, and trade-offs—never on personal traits or experience level.
- **Zero tolerance for harassment:** Harassment, discrimination, doxxing, trolling, or exclusionary behavior will result in immediate removal from project spaces.`
      },
      {
        id: 'enforcement',
        title: '2. Enforcement & Reporting Guidelines',
        isEnforcement: true,
        content: ''
      }
    ]
  },
  {
    id: 'community-citizenship',
    name: 'Community & Citizenship',
    summary: 'Inclusive community charter highlighting positive citizenship, mutual respect, and collaborative values.',
    sections: [
      {
        id: 'purpose',
        title: '1. Purpose & Inclusivity',
        content: `A primary goal of **{PROJECT_NAME}** is to be inclusive to the largest number of contributors, with the most varied and diverse backgrounds possible. We are committed to providing a friendly, safe, and welcoming environment for all.

This Code of Conduct outlines our expectations for everyone participating in **{SCOPE_CHANNELS}**.`
      },
      {
        id: 'citizenship',
        title: '2. Open Source Citizenship',
        content: `A healthy community requires active positive citizenship:

- **Active Participation:** Participate in an authentic and constructive way that advances **{PROJECT_NAME}**.
- **Collaboration Over Conflict:** Seek consensus and understanding during technical disagreements.
- **Support Newcomers:** Guide new contributors with patience and constructive guidance.
- **Prompt Communication:** Alert community leaders promptly if you notice anyone experiencing harassment or distress.`
      },
      {
        id: 'enforcement',
        title: '3. Enforcement Guidelines',
        isEnforcement: true,
        content: ''
      }
    ]
  }
];

// 2. CONTACT.md Templates
export const CONTACT_TEMPLATES: GenericTemplate[] = [
  {
    id: 'standard-contact',
    name: 'Standard',
    summary: 'Clear breakdown of reporting channels, general inquiries, security issues, and response expectations.',
    content: `# Contact Information — {PROJECT_NAME}

Welcome to **[{PROJECT_NAME}]({PROJECT_URL})**. We value open communication, constructive collaboration, and the safety of our community.

Use the appropriate contact method below based on the nature of your inquiry.

---

## 1. Primary Contact Person

- **Lead / Steward:** {PRIMARY_CONTACT}
- **Direct Email / Channel:** \`{PRIMARY_EMAIL}\`
- **Role:** Handles general inquiries, governance, and community coordination.

---

## 2. Code of Conduct & Safety Inquiries

For private, confidential reports regarding violations of our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md):

- **Private Reporting Email:** \`{CONDUCT_EMAIL}\`
- **Target Response Window:** Within **{RESPONSE_SLA}**
- **Confidentiality:** Reports are kept strictly confidential. In the event of a conflict of interest involving a review member, that person is automatically recused.

---

## 3. Security Vulnerabilities

Please **do not** open public issues for security vulnerabilities.

- **Security Advisories:** [GitHub Security Advisories]({PROJECT_URL}/security/advisories)
- **Security Contact:** \`{SECURITY_EMAIL}\`
- **Security Policy:** Detailed disclosure terms are in [SECURITY.md](SECURITY.md).

---

## 4. Community & Discussion Channels

For general questions, discussions, feature proposals, and community chat:

- **Public Discussions:** [{PROJECT_URL}/discussions]({PROJECT_URL}/discussions)
- **Issue Tracker:** [{PROJECT_URL}/issues]({PROJECT_URL}/issues)
- **Community Chat:** {COMMUNITY_CHAT}

---

## 5. Response Times

**{PROJECT_NAME}** is maintained through open collaboration. While critical security and conduct issues are acknowledged within **{RESPONSE_SLA}**, general feature requests and issues are reviewed asynchronously.`
  },
  {
    id: 'minimalist-contact',
    name: 'Minimalist',
    summary: 'Clean, one-page directory for solo projects and small libraries.',
    content: `# Contact — {PROJECT_NAME}

For inquiries regarding **[{PROJECT_NAME}]({PROJECT_URL})**, please use the designated channels:

- **Primary Contact:** {PRIMARY_CONTACT} (\`{PRIMARY_EMAIL}\`)
- **Code of Conduct Reports:** \`{CONDUCT_EMAIL}\` (refer to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md))
- **Security Issues:** \`{SECURITY_EMAIL}\` (refer to [SECURITY.md](SECURITY.md))
- **Community Discussions:** [{PROJECT_URL}/issues]({PROJECT_URL}/issues)

We aim to acknowledge sensitive conduct and security inquiries within **{RESPONSE_SLA}**.`
  }
];

// 3. SECURITY.md Templates
export const SECURITY_TEMPLATES: GenericTemplate[] = [
  {
    id: 'standard-security',
    name: 'Standard',
    summary: 'Industry-standard GitHub security policy with supported versions table, reporting steps, and disclosure timeline.',
    content: `# Security Policy — {PROJECT_NAME}

The **{PROJECT_NAME}** team takes the security of our software and users seriously. This document outlines our supported versions, reporting procedures, and disclosure policies.

---

## Supported Versions

Please refer to the table below for currently supported versions receiving security updates:

| Version | Supported          | Security Patches |
| ------- | ------------------ | ---------------- |
| Latest  | :white_check_mark: | Active           |
| Prior   | :white_check_mark: | Critical only    |
| Older   | :x:                | Unsupported      |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report vulnerabilities privately using one of the following methods:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Navigate to the [Security Advisories]({PROJECT_URL}/security/advisories) tab on GitHub and click **"Report a vulnerability"**.

2. **Direct Security Contact:**  
   Email our primary security contact:  
   - **Primary Contact:** {PRIMARY_CONTACT}  
   - **Security Email:** \`{SECURITY_EMAIL}\`  
   - **Response SLA:** We will acknowledge receipt within **{RESPONSE_SLA}**.

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:
- A clear description of the vulnerability and potential impact.
- Step-by-step instructions or a minimal Proof of Concept (PoC) to reproduce the behavior.
- Affected versions, platforms, and configuration details.
- Any suggested mitigations or patches (if available).

---

## Vulnerability Handling & Disclosure Timeline

1. **Acknowledgment:** Within **{RESPONSE_SLA}**, we will confirm receipt of your report.
2. **Assessment:** Within **{ASSESSMENT_WINDOW}**, we will validate the vulnerability, assess its severity, and determine an initial remediation plan.
3. **Patch & Testing:** We will prepare and test a security advisory and patch.
4. **Coordinated Disclosure:** We kindly request that you refrain from disclosing the vulnerability publicly until a release has been published.

---

## Contributor Recognition

We appreciate and credit security researchers who discover and responsibly disclose vulnerabilities in accordance with this policy. Check [CONTACT.md](CONTACT.md) for additional maintainer contacts.`
  },
  {
    id: 'minimalist-security',
    name: 'Minimalist',
    summary: 'Concise security disclosure notice for lightweight packages and utilities.',
    content: `# Security Policy — {PROJECT_NAME}

If you believe you have found a security vulnerability in **[{PROJECT_NAME}]({PROJECT_URL})**, please report it responsibly:

- **Contact:** Email **{PRIMARY_CONTACT}** at \`{SECURITY_EMAIL}\`
- **SLA:** We will acknowledge your report within **{RESPONSE_SLA}**.

Please **do not** open public issues for security concerns. We will work with you to analyze the vulnerability, prepare a fix, and coordinate a public release.`
  }
];

// 4. CODEOWNERS Templates
export const CODEOWNERS_TEMPLATES: GenericTemplate[] = [
  {
    id: 'standard-codeowners',
    name: 'Standard',
    summary: 'Standard GitHub/GitLab CODEOWNERS format with global ownership, documentation, and sensitive file coverage.',
    content: `# CODEOWNERS for {PROJECT_NAME}
# This file defines individuals or teams responsible for code in this repository.
# Syntax reference: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

# 1. Global Catch-All Owner
# These owners will be the default reviewers for everything in the repo:
* {GLOBAL_OWNER}

# 2. Critical Configuration & Workflows
/.github/ {GLOBAL_OWNER}
/package.json {GLOBAL_OWNER}
/tsconfig.json {GLOBAL_OWNER}

# 3. Security & Governance Policies
/SECURITY.md {SECURITY_OWNER}
/CODE_OF_CONDUCT.md {PRIMARY_OWNER}
/CONTACT.md {PRIMARY_OWNER}

# 4. Core Source Code
/src/ {GLOBAL_OWNER}

# 5. Documentation
/docs/ {DOCS_OWNER}
*.md {DOCS_OWNER}
`
  },
  {
    id: 'component-codeowners',
    name: 'Component-Based',
    summary: 'Separates frontend, backend, CI/CD, and docs across distinct maintainer handles.',
    content: `# CODEOWNERS for {PROJECT_NAME}
# Component-based review routing

# Global fallback
* {GLOBAL_OWNER}

# Core application logic
/src/core/ {GLOBAL_OWNER}
/src/api/ {GLOBAL_OWNER}

# User Interface & Frontend
/src/ui/ {PRIMARY_OWNER}
/src/components/ {PRIMARY_OWNER}

# CI/CD and deployment
/.github/workflows/ {GLOBAL_OWNER}
/Dockerfile {GLOBAL_OWNER}

# Documentation & Readmes
/docs/ {DOCS_OWNER}
/README.md {DOCS_OWNER}
/CONTRIBUTING.md {PRIMARY_OWNER}
`
  }
];

export const PRESET_CUSTOM_SECTIONS = [
  {
    title: 'Diversity, Equity & Inclusion Commitment',
    content: `**{PROJECT_NAME}** is committed to actively fostering diversity and inclusion. We recognize that open source has historically had barriers to entry for underrepresented groups. 

We prioritize equitable participation by:
- Offering mentorship and "good first issue" pathways for new contributors;
- Encouraging contributions beyond code, including documentation, design, accessibility testing, and community support;
- Providing a supportive space where questions are welcomed without condescension.`
  },
  {
    title: 'AI & Automated Contribution Policy',
    content: `Contributors to **{PROJECT_NAME}** may use AI coding assistants and LLMs under the following conditions:

- **Human Accountability:** You are personally responsible for verifying the accuracy, safety, licensing, and security of any code or text submitted.
- **No Automated PR Flooding:** Automated generation of mass pull requests or issues without prior maintainer discussion is considered disruptive conduct.
- **Disclosure:** Please include a brief disclosure in the pull request description if significant portions were AI-generated.`
  },
  {
    title: 'Health, Well-being & Burnout Boundaries',
    content: `We recognize that open-source contributors and maintainers are humans with jobs, families, and personal lives. 

To prevent burnout:
- Respect volunteer time: Responses to issues and PRs may take several days. Please do not repeatedly ping maintainers.
- Asynchronous by default: No contributor is expected to be on call outside of emergency security patches.
- Maintainers reserve the right to pause discussions that become counterproductive.`
  },
  {
    title: 'Commercial Neutrality & Sponsorship Ethics',
    content: `While commercial companies and sponsors are encouraged to contribute to **{PROJECT_NAME}**, project technical governance remains strictly merit-based and independent.

- Commercial entities may not demand priority review or exclusive feature control outside of normal community triage.
- Direct marketing, spam, or promotional solicitation in repository issues or discussions is strictly prohibited.`
  }
];
