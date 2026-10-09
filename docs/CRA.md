# The CRA reporting clock, in one page

**Regulation (EU) 2024/2847, the Cyber Resilience Act.** Article 14 obligations apply from **11 September 2026**; the
rest of the regulation applies from **11 December 2027**.

## Who

Manufacturers of products with digital elements (software and connected hardware) made available on the EU market,
including products placed on the market before the dates above.

## What triggers it

1. An **actively exploited vulnerability** in the product: there is reliable evidence that a malicious actor has exploited
   it without the owner's permission.
2. A **severe incident** affecting the security of the product.

CRA Clock handles (1) for third-party components using CISA KEV as the evidence source.

## The clock

| Deadline | Report | Contents (early warning and notification as CRA Clock drafts them) |
|---|---|---|
| 24 h after awareness | Early warning | Exploited yes or no; product; Member States where it is available |
| 72 h | Notification | General information; initial severity assessment; corrective or mitigating measures; measures users can take; sensitivity of the information |
| 14 days after a corrective measure is available | Final report | Description and severity; malicious actor information if known; details of the security update |

Under Articles 14 and 16, reports go through the **single reporting platform** managed by ENISA, which routes them to the
coordinating CSIRT and ENISA. Check the Commission's reporting page below for the current submission route.

## What CRA Clock does not do

- Decide whether your product is in scope.
- Submit to ENISA.
- Know when you first became aware through other channels (the issue says so).

Primary sources: [Regulation (EU) 2024/2847 on EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) (Article 14,
reporting obligations; Article 71, entry into force and application) and the European Commission's
[CRA reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

Secondary: [STAR, CRA Article 14](https://star.global/insights/articles/cyber-resilience-act-article-14-reporting-requirements/),
[HackerOne, CRA reporting goes live](https://www.hackerone.com/blog/eu-cra-reporting-requirements).
