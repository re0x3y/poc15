package models

// BIG role codes for Dutch healthcare professionals.
const (
	BIGRoleHuisarts        = "01.001"
	BIGRoleRadioloog       = "01.015"
	BIGRoleCardioloog      = "01.003"
	BIGRoleVerpleegkundige = "30.001"
)

// DICOM modalities.
const (
	ModalityCT = "CT"
	ModalityMR = "MR"
	ModalityXR = "XR"
	ModalityUS = "US"
	ModalityNM = "NM"
	ModalityPT = "PT"
)

// Authorization decision values.
const (
	DecisionPermit = "Permit"
	DecisionDeny   = "Deny"
)
