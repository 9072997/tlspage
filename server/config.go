package main

import "time"

const Origin = "tls.page"
const PackageNameVersion = "tls.page v1.0.0"
const DqliteTimeout = 60 * time.Second
const ShutdownTimeout = 5 * time.Second
const ACMEDirectoryURL = "https://acme.zerossl.com/v2/DV90"
const ACMETimeout = 10 * time.Minute
const ACMERetries = 3
const ACMERetryDelay = 15 * time.Second
const CAAIdentifier = "sectigo.com"
