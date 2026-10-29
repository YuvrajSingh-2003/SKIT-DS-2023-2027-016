# Web page phishing detection — Hannousse & Yahiouche (2021)

- **File:** `dataset_B_05_2020.csv`
  - SHA-256 `21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c` (matches the Mendeley
    API's `sha256_hash`)
  - 3,661,166 bytes, 11,430 rows (5,715 legitimate, 5,715 phishing), 89 columns
  - ChainShield uses only the `url` and `status` columns.
- **Source:** Mendeley Data, DOI [10.17632/c2gw7fy2j4.3](https://data.mendeley.com/datasets/c2gw7fy2j4/3)
  (version 3, 25 June 2021).
- **Retrieved:** 2026-10-29 via the Mendeley public API (file id
  `575316f4-ee1d-453e-a04f-7b950915b61b`).
- **Licence:** CC BY 4.0. Redistribution is permitted with attribution. This file and this note
  provide the attribution. No changes were made to the CSV.
- **Citation:** A. Hannousse, S. Yahiouche, "Towards benchmark datasets for machine learning based
  website phishing detection: An experimental study", *Engineering Applications of Artificial
  Intelligence* 104 (2021). arXiv:2010.12847.
- **Collection** (paper §4.1), built May 2020:
  - **Legitimate:** 6,000 URLs crawled from the Alexa top-500 domains (12 URLs per domain), plus
    still-active legitimate URLs from Sahingoz et al., originally from Yandex.
  - **Phishing:** PhishTank and OpenPhish.
  - **Cleaning:** duplicates and dead URLs removed; at most 12 URLs per domain.
- **Label caveats:**
  - "Legitimate" means *crawled from popular sites / a prior legitimate list*, not individually
    verified.
  - Phishing labels are feed-reported (PhishTank is community-verified; OpenPhish is automated).
  - The snapshot is from 2020, so it does not represent current phishing.
