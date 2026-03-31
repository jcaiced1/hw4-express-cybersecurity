import ejs from "ejs";
import express from "express";
import mimeDb from "mime-db";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const navLinks = [
  { href: "/", label: "Home" },
  { href: "/threats", label: "Threats" },
  { href: "/protection", label: "Protection" },
  { href: "/incident-response", label: "Incident Response" },
  { href: "/security-awareness", label: "Security Awareness" },
];

const fallbackKev = [
  {
    cveID: "CVE-2025-0001",
    vendorProject: "Example Vendor",
    product: "Edge Gateway",
    vulnerabilityName: "Authentication Bypass Vulnerability",
    shortDescription: "Attackers can bypass authentication and gain administrative access.",
    dateAdded: "2026-03-01",
    requiredAction: "Apply vendor patches and restrict public exposure.",
    knownRansomwareCampaignUse: "Unknown",
  },
  {
    cveID: "CVE-2025-0002",
    vendorProject: "Example Vendor",
    product: "Mail Server",
    vulnerabilityName: "Remote Code Execution Vulnerability",
    shortDescription: "A crafted request can execute arbitrary code on the server.",
    dateAdded: "2026-02-25",
    requiredAction: "Patch immediately and review suspicious outbound traffic.",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2025-0003",
    vendorProject: "Example Vendor",
    product: "VPN Appliance",
    vulnerabilityName: "Privilege Escalation Vulnerability",
    shortDescription: "An attacker can raise privileges after initial access.",
    dateAdded: "2026-02-17",
    requiredAction: "Rotate credentials and deploy the latest firmware.",
    knownRansomwareCampaignUse: "Unknown",
  },
];

app.locals.courseName = "CST336 Internet Programming";
app.locals.studentName = "Jose Caicedo";
app.locals.currentYear = new Date().getFullYear();
app.locals.apiName = "CISA Known Exploited Vulnerabilities Catalog";
app.locals.packageName = "mime-db";

app.engine("ejs", ejs.__express);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

function getAttachmentExamples() {
  const targets = [
    "application/pdf",
    "application/zip",
    "text/html",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/x-msdownload",
  ];

  return targets
    .map((type) => {
      const entry = mimeDb[type];
      if (!entry) {
        return null;
      }

      return {
        type,
        extensions: entry.extensions || [],
        source: entry.source || "unknown",
        charset: entry.charset || "n/a",
      };
    })
    .filter(Boolean);
}

function getRiskyExtensions() {
  return [
    { extension: ".zip", note: "Compressed archives can hide multiple files and scripts." },
    { extension: ".html", note: "HTML attachments can imitate login pages or redirect users." },
    { extension: ".pdf", note: "PDFs are common in phishing because they look professional." },
    { extension: ".docx", note: "Office documents are routine in business workflows and lower suspicion." },
    { extension: ".exe", note: "Executable files deserve extra caution before opening or downloading." },
  ].map((item) => {
    const entry = getAttachmentExamples().find((example) =>
      example.extensions.includes(item.extension.replace(".", ""))
    );

    return {
      ...item,
      mimeType: entry?.type || "not found in package lookup",
    };
  });
}

async function getKevFeed() {
  try {
    const response = await fetch(CISA_KEV_URL);
    if (!response.ok) {
      throw new Error(`CISA request failed with status ${response.status}`);
    }

    const data = await response.json();
    const vulnerabilities = Array.isArray(data?.vulnerabilities)
      ? data.vulnerabilities.slice(0, 5)
      : [];

    if (!vulnerabilities.length) {
      throw new Error("CISA response did not include vulnerability records.");
    }

    return {
      sourceLive: true,
      catalogVersion: data.catalogVersion || "current",
      count: data.count || vulnerabilities.length,
      vulnerabilities,
    };
  } catch (error) {
    return {
      sourceLive: false,
      catalogVersion: "fallback",
      count: fallbackKev.length,
      vulnerabilities: fallbackKev,
      error: error.message,
    };
  }
}

function renderPage(res, view, pageData) {
  return res.render(view, {
    navLinks,
    ...pageData,
  });
}

app.get("/", async (req, res) => {
  const kevFeed = await getKevFeed();

  return renderPage(res, "index", {
    title: "Cybersecurity Basics",
    activePath: "/",
    kevFeed,
    packageExamples: getAttachmentExamples().slice(0, 3),
  });
});

app.get("/threats", async (req, res) => {
  const kevFeed = await getKevFeed();

  return renderPage(res, "threats", {
    title: "Cybersecurity Threats",
    activePath: "/threats",
    kevFeed,
  });
});

app.get("/protection", (req, res) => {
  return renderPage(res, "protection", {
    title: "System Protection",
    activePath: "/protection",
    attachmentExamples: getAttachmentExamples(),
  });
});

app.get("/incident-response", async (req, res) => {
  const kevFeed = await getKevFeed();

  return renderPage(res, "incident-response", {
    title: "Incident Response",
    activePath: "/incident-response",
    recentCases: kevFeed.vulnerabilities.slice(0, 3),
    apiLive: kevFeed.sourceLive,
  });
});

app.get("/security-awareness", (req, res) => {
  return renderPage(res, "security-awareness", {
    title: "Security Awareness",
    activePath: "/security-awareness",
    riskyExtensions: getRiskyExtensions(),
  });
});

app.use((req, res) => {
  return res.status(404).render("not-found", {
    title: "Page Not Found",
    navLinks,
    activePath: "",
  });
});

if (import.meta.url === `file://${process.argv[1]}`) {
  app.listen(PORT, () => {
    console.log(`HW4 server running on http://localhost:${PORT}`);
  });
}

export default app;
