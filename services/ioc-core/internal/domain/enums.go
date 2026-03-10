package domain

type IoCType string

const (
	IoCTypeUnspecified IoCType = "unspecified"
	IoCTypeIP          IoCType = "ip"
	IoCTypeDomain      IoCType = "domain"
	IoCTypeURL         IoCType = "url"
	IoCTypeHashMD5     IoCType = "hash_md5"
	IoCTypeHashSHA1    IoCType = "hash_sha1"
	IoCTypeHashSHA256  IoCType = "hash_sha256"
	IoCTypeFilePath    IoCType = "file_path"
)

func (it IoCType) IsValid() bool {
	switch it {
	case IoCTypeIP, IoCTypeDomain, IoCTypeURL, IoCTypeHashMD5,
		IoCTypeHashSHA1, IoCTypeHashSHA256, IoCTypeFilePath:
		return true
	}
	return false
}

func (it IoCType) String() string {
	return string(it)
}

type Severity string

const (
	SeverityUnspecified Severity = "unspecified"
	SeverityInfo        Severity = "info"
	SeverityLow         Severity = "low"
	SeverityMedium      Severity = "medium"
	SeverityHigh        Severity = "high"
	SeverityCritical    Severity = "critical"
)

func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium,
		SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func (s Severity) String() string {
	return string(s)
}

func (s Severity) ToInt() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

type Verdict string

const (
	VerdictUnspecified   Verdict = "unspecified"
	VerdictBenign        Verdict = "benign"
	VerdictSuspicious    Verdict = "suspicious"
	VerdictMalicious     Verdict = "malicious"
	VerdictFalsePositive Verdict = "false_positive"
	VerdictUnknown       Verdict = "unknown"
)

func (v Verdict) IsValid() bool {
	switch v {
	case VerdictBenign, VerdictSuspicious, VerdictMalicious, VerdictUnknown:
		return true
	}
	return false
}

func (v Verdict) String() string {
	return string(v)
}

type ThreatCategory string

const (
	ThreatCategoryUnspecified ThreatCategory = "unspecified"
	ThreatCategoryMalware     ThreatCategory = "malware"
	ThreatCategoryBotnet      ThreatCategory = "botnet"
	ThreatCategoryC2          ThreatCategory = "c2"
	ThreatCategoryExploit     ThreatCategory = "exploit"
	ThreatCategoryPhishing    ThreatCategory = "phishing"
	ThreatCategorySpam        ThreatCategory = "spam"
)

func (tc ThreatCategory) IsValid() bool {
	switch tc {
	case
		ThreatCategoryBotnet, ThreatCategoryC2, ThreatCategoryExploit,
		ThreatCategoryMalware, ThreatCategoryPhishing, ThreatCategorySpam:
		return true
	}
	return false
}

func (tc ThreatCategory) String() string {
	return string(tc)
}

type TLP string

const (
	TLPUnspecified TLP = "unspecified"
	TLPClear       TLP = "clear"
	TLPGreen       TLP = "green"
	TLPAmber       TLP = "amber"
	TLPAmberStrict TLP = "amber_strict"
	TLPRed         TLP = "red"
)

func (tlp TLP) IsValid() bool {
	switch tlp {
	case TLPAmber, TLPAmberStrict, TLPClear, TLPGreen, TLPRed:
		return true
	}
	return false
}

func (tlp TLP) String() string {
	return string(tlp)
}

type KillChainPhase string

const (
	PhaseUnspecified    KillChainPhase = "unspecified"
	PhaseReconnaissance KillChainPhase = "reconnaissance"
	PhaseWeaponization  KillChainPhase = "weaponization"
	PhaseDelivery       KillChainPhase = "delivery"
	PhaseExploitation   KillChainPhase = "exploitation"
	PhaseInstallation   KillChainPhase = "installation"
	PhaseC2             KillChainPhase = "command_and_control"
	PhaseActions        KillChainPhase = "actions_on_objectives"
)

func (kcp KillChainPhase) IsValid() bool {
	switch kcp {
	case PhaseActions, PhaseC2, PhaseDelivery, PhaseWeaponization,
		PhaseExploitation, PhaseInstallation, PhaseReconnaissance:
		return true

	}
	return false
}

func (kcp KillChainPhase) String() string {
	return string(kcp)
}

type EnrichmentSource string

const (
	EnrichmentSourceUnspecified EnrichmentSource = "unspecified"
	EnrichmentSourceVirusTotal  EnrichmentSource = "virustotal"
	EnrichmentSourceAbuseIPDB   EnrichmentSource = "abuseipdb"
	EnrichmentSourceOTX         EnrichmentSource = "otx"
	EnrichmentHybridAnalysis    EnrichmentSource = "hybrid_analysis"
	// Source not opened yet
	// EnrichmentSourceShodan      EnrichmentSource = "shodan"
	// EnrichmentSourceCrowdStrike EnrichmentSource = "crowdstrike"
	// EnrichmentAnyRun            EnrichmentSource = "anyrun"
)

func (es EnrichmentSource) IsValid() bool {
	switch es {
	case EnrichmentSourceVirusTotal, EnrichmentSourceAbuseIPDB,
		EnrichmentSourceOTX, EnrichmentHybridAnalysis:
		return true
	}
	return false
}

func (es EnrichmentSource) String() string {
	return string(es)
}

type EnrichmentStatus string

const (
	EnrichmentStatusUnspecified EnrichmentStatus = "unspecified"
	EnrichmentProcessing        EnrichmentStatus = "processing"
	EnrichmentStatusCompleted   EnrichmentStatus = "completed"
	EnrichmentStatusFailed      EnrichmentStatus = "failed"
	EnrichmentStatusPartial     EnrichmentStatus = "partial"
)

func (es EnrichmentStatus) IsValid() bool {
	switch es {
	case EnrichmentProcessing,
		EnrichmentStatusCompleted, EnrichmentStatusFailed,
		EnrichmentStatusPartial:
		return true
	}
	return false
}

func (es EnrichmentStatus) String() string {
	return string(es)
}

type RelationType string

const (
	RelationTypeUnspecified      RelationType = "unspecified"
	RelationTypeSameCampaign     RelationType = "same_campaign"
	RelationTypeSameThreatActor  RelationType = "same_threat_actor"
	RelationTypeSameFamily       RelationType = "same_family"
	RelationTypeResolvesTo       RelationType = "resolves_to"
	RelationTypeCommunicatesWith RelationType = "communicates_with"
	RelationTypeDownloadedFrom   RelationType = "downloaded_from"
	RelationTypeDrops            RelationType = "drops"
)

func (rt RelationType) IsValid() bool {
	switch rt {
	case RelationTypeSameCampaign, RelationTypeSameThreatActor,
		RelationTypeSameFamily, RelationTypeResolvesTo,
		RelationTypeCommunicatesWith, RelationTypeDownloadedFrom,
		RelationTypeDrops:
		return true
	}
	return false
}

func (rt RelationType) String() string {
	return string(rt)
}
