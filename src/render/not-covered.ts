/* What every report says the tool does not look at (PLAN.md, "Not covered in v1"). */
export const NOT_COVERED: readonly string[] = [
  'The key exchange between CloudFront and your origin.',
  'AWS Transfer Family SFTP endpoints. Post-quantum SSH policies exist for them and are a separate protocol.',
  'S3 negotiates post-quantum key exchange on the server side with nothing to configure, so there is nothing to report.',
  'Application code, including the TLS libraries and SDK versions your own software uses.',
  'Clouds other than AWS.',
  'Module calls whose inputs the engine cannot see. The resources inside them are not scanned.',
  'Anything behind an expression the engine could not resolve. Those items are listed as could not check.',
];
