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

Reports go through the **ENISA Single Reporting Platform**, which routes them to the coordinating CSIRT and ENISA.

## What CRA Clock does not do

- Decide whether your product is in scope.
- Submit to ENISA.
- Know when you first became aware through other channels (the issue says so).

Sources: [STAR, CRA Article 14](https://star.global/posts/cyber-resilience-act-article-14-reporting-requirements/),
[HackerOne, CRA reporting goes live](https://www.hackerone.com/blog/eu-cra-reporting-requirements).
