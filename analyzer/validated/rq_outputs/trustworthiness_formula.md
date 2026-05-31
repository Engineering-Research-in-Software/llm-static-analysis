# Trustworthiness Score Formula

## Normalized inputs
  inv_hf  = 1 - hallucinationFrequency           # range [0,1]
  ta_norm = technicalAccuracy / 10               # range [0,1]
  eca_norm= effectChainAwareness / 10            # range [0,1]
  asc_norm= attackSurfaceCoverage                # range [0,1]

## Baseline (equal weights)
  TS_equal = 0.25 * (inv_hf + ta_norm + eca_norm + asc_norm)

## PCA-derived weights (from PC1 on validated/conclusions.json)
  w_1-HF = 0.0554
  w_TA_10 = 0.3158
  w_ECA_10 = 0.3269
  w_ASC = 0.3019

  TS_pca = 0.0554*1-HF + 0.3158*TA/10 + 0.3269*ECA/10 + 0.3019*ASC

## Correlation between TS_equal and TS_pca: r = 0.947