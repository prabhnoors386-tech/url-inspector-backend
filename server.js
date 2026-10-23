const whois = require('whois-json');

// --- URL INSPECTOR API ---
app.post('/api/inspect-url', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    // Extract the clean domain name (e.g., from https://www.google.com/search to google.com)
    let domain = url.trim();
    if (domain.startsWith('http')) {
      domain = new URL(domain).hostname;
    }
    domain = domain.replace(/^www\./, '');

    // Fetch WHOIS data
    const whoisData = await whois(domain);
    const creationDate =
      whoisData.creationDate || whoisData.createdDate || 'Unknown';

    let ageInDays = 'Unknown';
    let isSuspicious = false;
    let riskStatus = 'Unknown Risk';

    // Calculate the age in days
    if (creationDate !== 'Unknown') {
      const created = new Date(creationDate);
      const diffTime = Math.abs(new Date() - created);
      ageInDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      // Flag as suspicious if the domain is less than 30 days old
      if (ageInDays < 30) {
        isSuspicious = true;
        riskStatus = 'High Risk - Brand New Domain';
      } else {
        riskStatus = 'Safe - Established Domain';
      }
    }

    res.json({
      data: {
        domain: domain,
        creationDate: creationDate,
        ageInDays: ageInDays,
        riskStatus: riskStatus,
        isSuspicious: isSuspicious,
      },
    });
  } catch (error) {
    console.error('URL Scan Error:', error);
    res
      .status(500)
      .json({ error: 'Failed to inspect URL. It might be invalid.' });
  }
});
