package validator

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

type Validator struct {
	validate *validator.Validate
}

func New() *Validator {
	v := validator.New()

	v.RegisterValidation("ioc_type", validateIoCType)
	v.RegisterValidation("severity", validateSeverity)
	v.RegisterValidation("verdict", validateVerdict)
	v.RegisterValidation("ip_addresses", validateIPAddress)
	v.RegisterValidation("domain_name", validateDomainName)
	v.RegisterValidation("url_string", validateURLString)
	v.RegisterValidation("hash_md5", validateHashMD5)
	v.RegisterValidation("hash_sha1", validateHashSHA1)
	v.RegisterValidation("hash_sha256", validateHashSHA256)
	v.RegisterValidation("file_path", validateFilePath)
	v.RegisterValidation("registry_key", validateRegistryKey)
	v.RegisterValidation("mutex", validateMutex)
	v.RegisterValidation("email", validateEmail)
	v.RegisterValidation("crypto_address", validateCryptoAddress)
	v.RegisterValidation("cloud_identity", validateCloudIdentity)
	v.RegisterValidation("ja3_fingerprint", validateJa3Fingerprint)

	return &Validator{validate: v}

}

// Validate struct
func (v *Validator) ValidateStruct(s *interface{}) error {
	return v.validate.Struct(s)
}

// Validate IP Addresses
func (v *Validator) ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

func (v *Validator) ValidateDomain(domain string) error {
	domainRegex := `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(domainRegex, domain)
	if err != nil || !matched {
		return fmt.Errorf("invalid domain: %s", domain)
	}
	return nil
}

func (v *Validator) ValidateURL(url_str string) error {
	_, err := url.ParseRequestURI(url_str)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", url_str)
	}
	return nil
}

func (v *Validator) ValidateHash(h_str, h_typ string) error {
	h_str = strings.ToLower(h_str)

	switch h_typ {
	case "md5":
		return v.ValidateHashMD5(h_str)
	case "sha1":
		return v.ValidateHashSHA1(h_str)
	case "sha256":
		return v.ValidateHashSHA256(h_str)
	default:
		return fmt.Errorf("unsupported hash type: %s", h_typ)
	}
}

func (v *Validator) ValidateHashMD5(h_str string) error {
	matched, _ := regexp.MatchString(`^[a-f0-9]{32}$`, h_str)
	if !matched {
		return fmt.Errorf("invalid hash MD5: %s", h_str)
	}
	return nil
}

func (v *Validator) ValidateHashSHA1(h_str string) error {
	matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, h_str)
	if !matched {
		return fmt.Errorf("invalid hash SHA1: %s", h_str)
	}
	return nil
}

func (v *Validator) ValidateHashSHA256(h_str string) error {
	matched, _ := regexp.MatchString(`^[a-f0-9]{64}$`, h_str)
	if !matched {
		return fmt.Errorf("invalid hash SHA256: %s", h_str)
	}
	return nil
}

func (v *Validator) ValidateFilePath(file_path string) error {
	if file_path == "" {
		return fmt.Errorf("file path is empty")
	}
	clean_path := filepath.Clean(file_path)
	if clean_path == "." {
		return fmt.Errorf("invalid file path")
	}
	return nil
}

func (v *Validator) ValidateRegistryKey(registry_key string) error {
	registryRegex := `^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\.+`
	matched, _ := regexp.MatchString(registryRegex, registry_key)
	if !matched {
		return fmt.Errorf("invalid registry key: %s", registry_key)
	}
	return nil
}

func (v *Validator) ValidateMutex(mu string) error {
	if len(mu) < 3 || len(mu) > 255 {
		return fmt.Errorf("invalid mutex: %s", mu)
	}
	return nil
}

func (v *Validator) ValidateEmail(email string) error {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	if !matched {
		return fmt.Errorf("invalid email: %s", email)
	}
	return nil
}

func (v *Validator) ValidateCryptoAddress(crt_addr string) error {
	btcRegex := regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$`)
	ethRegex := regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	if btcRegex.MatchString(crt_addr) || ethRegex.MatchString(crt_addr) {
		return nil
	}
	return fmt.Errorf("invalid crypto address: %s", crt_addr)
}

func (v *Validator) ValidateCloudIdentity(cl_identity string) error {
	if strings.Contains(cl_identity, "@") {
		return v.ValidateEmail(cl_identity)
	}
	if strings.HasPrefix(cl_identity, "arn:") {
		return nil
	}
	return fmt.Errorf("invalid cloud identity")
}

func (v *Validator) ValidateJa3FingerPrint(ja3_str string) error {
	ja3Regex := `^[a-f0-9]{32}$`
	matched, _ := regexp.MatchString(ja3Regex, ja3_str)
	if !matched {
		return fmt.Errorf("invalid Ja3 fingerprint: %s", ja3_str)
	}
	return nil
}

// Custom validator
func validateIoCType(fl validator.FieldLevel) bool {
	valid_types := []string{"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
		"file_path", "registry_key", "mutex", "email", "crypto_address",
		"cloud_identity", "ja3_fingerprint"}
	value := fl.Field().String()
	for _, t := range valid_types {
		if value == t {
			return true
		}
	}
	return false
}

func validateSeverity(fl validator.FieldLevel) bool {
	valid_severities := []string{"info", "low", "medium", "high", "critical"}
	value := fl.Field().String()
	for _, s := range valid_severities {
		if value == s {
			return true
		}
	}
	return false
}

func validateVerdict(fl validator.FieldLevel) bool {
	valid_verdicts := []string{"benign", "suspicious", "malicious", "false_positive", "unknown"}
	value := fl.Field().String()
	for _, v := range valid_verdicts {
		if value == v {
			return true
		}
	}
	return false
}

func validateIPAddress(fl validator.FieldLevel) bool {
	return net.ParseIP(fl.Field().String()) != nil
}

func validateDomainName(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
		fl.Field().String())
	return matched
}

func validateURLString(fl validator.FieldLevel) bool {
	_, err := url.ParseRequestURI(fl.Field().String())
	return err == nil
}

func validateHashMD5(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{32}$`, fl.Field().String())
	return matched
}

func validateHashSHA1(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, fl.Field().String())
	return matched
}

func validateHashSHA256(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{64}$`, fl.Field().String())
	return matched
}

func validateFilePath(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return false
	}
	value_clean := filepath.Clean(value)
	if value_clean == "." {
		return false
	}
	return true
}

func validateRegistryKey(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\.+`, fl.Field().String())
	return matched
}

func validateMutex(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return len(value) > 3 && len(value) < 255
}

func validateEmail(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, fl.Field().String())
	return matched
}

func validateCryptoAddress(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	btcRegex := regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$`)
	ethRegex := regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	return btcRegex.MatchString(value) || ethRegex.MatchString(value)
}

func validateCloudIdentity(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if strings.Contains(value, "@") {
		return validateEmail(fl)
	}
	return strings.HasPrefix(value, "arn:")
}

func validateJa3Fingerprint(fl validator.FieldLevel) bool {
	matched, _ := regexp.MatchString(`^[a-f0-9]{32}$`, fl.Field().String())
	return matched
}
