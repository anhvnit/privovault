Pod::Spec.new do |s|
  s.name             = 'privovault_crypto'
  s.version          = '0.1.0'
  s.summary          = 'PrivoVault biometric key release (Keychain + Secure Enclave access control).'
  s.homepage         = 'https://privovault.com'
  s.license          = { :type => 'Proprietary' }
  s.author           = { 'PrivoVault' => 'privacy@privovault.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '15.0'
  s.frameworks       = 'LocalAuthentication', 'Security'
  s.swift_version    = '5.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
