const DEFAULT_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "dkim",
  "mail",
  "k1",
];

const DNS_TYPES = {
  TXT: 16,
  CNAME: 5,
};

const RESOLVERS = [
  {
    name: "Google DNS",
    headers: {},
    buildUrl: (recordName, type) =>
      `https://dns.google/resolve?name=${encodeURIComponent(recordName)}&type=${encodeURIComponent(type)}`,
  },
  {
    name: "Cloudflare DNS",
    headers: { accept: "application/dns-json" },
    buildUrl: (recordName, type) =>
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(recordName)}&type=${encodeURIComponent(type)}`,
  },
];

const form = document.getElementById("check-form");
const domainInput = document.getElementById("domain");
const selectorsInput = document.getElementById("selectors");
const submitButton = document.getElementById("submit-button");
const results = document.getElementById("results");
const status = document.getElementById("status");

function setStatus(message) {
  status.textContent = message;
}

function clearResults() {
  results.replaceChildren();
}

function normalizeDomain(value) {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function isValidDomain(domain) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
    domain,
  );
}

function parseSelectorList(value) {
  return [...new Set(value.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean))];
}

function decodeTxtRecord(data) {
  const matches = [...data.matchAll(/"([^"]*)"/g)];
  if (!matches.length) {
    return data;
  }

  return matches.map((match) => match[1]).join("");
}

async function fetchJson(url, headers = {}) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }

  return response.json();
}

async function resolveDns(name, type) {
  const failures = [];

  for (const resolver of RESOLVERS) {
    const url = resolver.buildUrl(name, type);

    try {
      const payload = await fetchJson(url, resolver.headers);
      return payload;
    } catch (error) {
      failures.push(`${resolver.name}: ${error.message}`);
    }
  }

  throw new Error(
    `DNS resolution failed for ${name} (${type}). Tried ${RESOLVERS.length} resolvers. ${
      failures.join(" | ") || "No resolver details were returned."
    }`,
  );
}

async function getAnswerRecords(name, type) {
  const payload = await resolveDns(name, type);
  return Array.isArray(payload.Answer) ? payload.Answer : [];
}

async function getTxtRecords(name) {
  const answers = await getAnswerRecords(name, "TXT");
  return answers
    .filter((answer) => answer.type === DNS_TYPES.TXT)
    .map((answer) => decodeTxtRecord(answer.data));
}

async function getCnameRecords(name) {
  const answers = await getAnswerRecords(name, "CNAME");
  return answers
    .filter((answer) => answer.type === DNS_TYPES.CNAME)
    .map((answer) => answer.data.replace(/\.$/, ""));
}

function buildResult(title, state, summary, details) {
  return { title, state, summary, details };
}

async function checkSpf(domain) {
  const txtRecords = await getTxtRecords(domain);
  const spfRecords = txtRecords.filter((record) => /^v=spf1\b/i.test(record));

  if (spfRecords.length === 1) {
    return buildResult("SPF", "success", "Exactly one SPF record was found.", spfRecords);
  }

  if (spfRecords.length > 1) {
    return buildResult(
      "SPF",
      "warning",
      "Multiple SPF records were found. Mail receivers may treat this as invalid.",
      spfRecords,
    );
  }

  return buildResult("SPF", "failure", "No SPF record was found.", [
    `Checked TXT records on ${domain}.`,
  ]);
}

async function checkDmarc(domain) {
  const host = `_dmarc.${domain}`;
  const txtRecords = await getTxtRecords(host);
  const dmarcRecords = txtRecords.filter((record) => /^v=dmarc1\b/i.test(record));

  if (dmarcRecords.length === 1) {
    return buildResult("DMARC", "success", "A DMARC policy record was found.", dmarcRecords);
  }

  if (dmarcRecords.length > 1) {
    return buildResult(
      "DMARC",
      "warning",
      "Multiple DMARC records were found.",
      dmarcRecords,
    );
  }

  return buildResult("DMARC", "failure", "No DMARC record was found.", [
    `Checked TXT records on ${host}.`,
  ]);
}

async function checkTlsRpt(domain) {
  const host = `_smtp._tls.${domain}`;
  const txtRecords = await getTxtRecords(host);
  const tlsRptRecords = txtRecords.filter((record) => /^v=tlsrptv1\b/i.test(record));

  if (tlsRptRecords.length) {
    return buildResult("TLS-RPT", "success", "A TLS reporting record was found.", tlsRptRecords);
  }

  return buildResult("TLS-RPT", "warning", "No TLS-RPT record was found.", [
    `Checked TXT records on ${host}.`,
  ]);
}

async function resolveDkimRecord(selector, domain) {
  const host = `${selector}._domainkey.${domain}`;
  const txtRecords = await getTxtRecords(host);
  const dkimRecords = txtRecords.filter((record) => /^v=dkim1\b/i.test(record));

  if (dkimRecords.length) {
    return { selector, host, records: dkimRecords };
  }

  const cnames = await getCnameRecords(host);
  for (const cname of cnames) {
    const targetTxtRecords = await getTxtRecords(cname);
    const targetDkimRecords = targetTxtRecords.filter((record) => /^v=dkim1\b/i.test(record));
    if (targetDkimRecords.length) {
      return {
        selector,
        host,
        records: targetDkimRecords,
        alias: cname,
      };
    }
  }

  return { selector, host, records: [] };
}

async function checkDkim(domain, selectors) {
  const checkedSelectors = selectors.length ? selectors : DEFAULT_SELECTORS;
  const findings = await Promise.all(
    checkedSelectors.map((selector) => resolveDkimRecord(selector, domain)),
  );

  const matches = findings.filter((finding) => finding.records.length > 0);
  if (matches.length) {
    return buildResult(
      "DKIM",
      "success",
      `Found DKIM records for ${matches.length} selector${matches.length === 1 ? "" : "s"}.`,
      matches.flatMap((match) => [
        `${match.selector}: ${match.records.join(" ")}`,
        ...(match.alias ? [`Alias target: ${match.alias}`] : []),
      ]),
    );
  }

  return buildResult(
    "DKIM",
    "warning",
    "No DKIM records were found for the checked selectors.",
    [
      `Checked selectors: ${checkedSelectors.join(", ")}`,
      selectors.length
        ? "Try a different selector if your domain publishes DKIM under another name."
        : "Provide known selectors to perform a more precise DKIM check.",
    ],
  );
}

async function getMtaStsPolicy(domain) {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;

  try {
    const response = await fetch(policyUrl);
    if (!response.ok) {
      throw new Error(
        `Policy request failed with status ${response.status} (${response.statusText || "unknown"}). This may be due to CORS restrictions.`,
      );
    }

    const policyText = await response.text();
    return {
      state: "success",
      details: policyText
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
      policyUrl,
    };
  } catch (error) {
    return {
      state: "warning",
      details: [
        `MTA-STS DNS record exists, but the policy file could not be read from the browser.`,
        `Policy URL: ${policyUrl}`,
        `Reason: ${error.message}`,
      ],
      policyUrl,
    };
  }
}

async function checkMtaSts(domain) {
  const host = `_mta-sts.${domain}`;
  const txtRecords = await getTxtRecords(host);
  const stsRecords = txtRecords.filter((record) => /^v=stsv1\b/i.test(record));

  if (!stsRecords.length) {
    return buildResult("MTA-STS", "warning", "No MTA-STS DNS record was found.", [
      `Checked TXT records on ${host}.`,
    ]);
  }

  const policy = await getMtaStsPolicy(domain);
  return buildResult(
    "MTA-STS",
    policy.state === "success" ? "success" : "warning",
    policy.state === "success"
      ? "An MTA-STS record and policy file were found."
      : "An MTA-STS DNS record was found, but the policy file could not be verified in-browser.",
    [...stsRecords, ...policy.details],
  );
}

function renderResult(result) {
  const article = document.createElement("article");
  article.className = "result-card";

  const header = document.createElement("div");
  header.className = "result-header";

  const title = document.createElement("h2");
  title.textContent = result.title;

  const badge = document.createElement("span");
  badge.className = `badge ${result.state}`;
  badge.textContent = result.state === "failure" ? "Missing" : result.state;

  header.append(title, badge);

  const summary = document.createElement("p");
  summary.className = "summary";
  summary.textContent = result.summary;

  const detailList = document.createElement("ul");
  detailList.className = "detail-list";

  result.details.forEach((detail) => {
    const item = document.createElement("li");
    item.textContent = detail;
    detailList.appendChild(item);
  });

  article.append(header, summary, detailList);
  return article;
}

async function runChecks(domain, selectors) {
  return Promise.all([
    checkSpf(domain),
    checkDkim(domain, selectors),
    checkDmarc(domain),
    checkTlsRpt(domain),
    checkMtaSts(domain),
  ]);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearResults();

  const domain = normalizeDomain(domainInput.value);
  const selectors = parseSelectorList(selectorsInput.value.toLowerCase());

  if (!isValidDomain(domain)) {
    setStatus("Enter a valid domain name, for example example.gov.uk.");
    return;
  }

  submitButton.disabled = true;
  setStatus(`Checking ${domain}...`);

  try {
    const checks = await runChecks(domain, selectors);
    checks.forEach((check) => results.appendChild(renderResult(check)));
    setStatus(`Finished checking ${domain}.`);
  } catch (error) {
    setStatus(`Unable to complete the checks. ${error.message}`);
  } finally {
    submitButton.disabled = false;
  }
});
