
CREATE TABLE IF NOT EXISTS "certificate" (
  -- Note: RFC 3280 (4.1.2.2  Serial number) states the serial number
  -- must be:
  --  * unique
  --  * non-negative integer
  --  * up to 20 octets (up to 2**160)
  --  * not longer than 20 octets
  --
  -- use NUMERIC as data type, it is defined as:
  --
  -- numeric  variable  user-specified precision, exact   up to 131072 digits before the decimal point; up to 16383 digits after the decimal point
  -- 
  -- serial_number is NULL for certificates that are
  -- not issued yet, therefore it can't be used as primary key
  serial_number NUMERIC PRIMARY KEY CHECK(serial_number > 0),

  -- SSL version (Note: SSL starts version at 0)
  version INTEGER CHECK(version >= 0),

  -- set to NULL when certificate was not issued yet
  -- (csr submitted but pending)
  start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  end_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,

  -- subject of certificate
  -- it is NOT unique as it may occur for current and revoked certificates
  subject TEXT NOT NULL CHECK(subject <> ''),

  -- issuer of the certificate
  -- issuer can be NULL for signing requests
  issuer TEXT CHECK(issuer <> ''),

  -- store fingerprints for subject data
  -- as serial_number and certificate content should be
  -- unique, enforce constraints
  -- fingerprint_* is not set (NULL) for certificates not
  -- issued yet
  fingerprint_md5 VARCHAR(32) UNIQUE DEFAULT NULL CHECK(fingerprint_md5 <> ''),
  fingerprint_sha1 VARCHAR(40) UNIQUE DEFAULT NULL CHECK(fingerprint_sha1 <> ''),

  -- certificate holds the base64 encoded public key
  -- it is NULL for pending certificates
  certificate TEXT UNIQUE CHECK(certificate <> ''),

  -- array of x509 extensions
  extension VARCHAR(128)[],

  -- store original signing request, can be NULL if
  -- original csr is missing.
  -- Note: This is NOT unique, because the same csr can be
  -- used, e.g. for reissue a certificate when the old has been
  -- revoked
  signing_request TEXT UNIQUE CHECK(signing_request <> ''),

  -- state is the current state of the certificate
  -- possible values are
  -- -1 - temporary: ?
  --  0 - pending: CSR submitted but not issued yet
  --  1 - valid: certificate is valid
  --  2 - revoked: certificate has been revoked
  --  3 - expired: certificate has been expired
  --  4 - invalid: certificate is invalid (usually the validity period has not started yet)
  state INTEGER NOT NULL CHECK(state >= 0),

  -- revocation_date, not NULL when certificate has been revoked
  revocation_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  -- revocation_reason reason for revocation
  -- possible values are
  --  0 - unspecified
  --  1 - keyCompromise
  --  2 - CACompromise
  --  3 - affiliationChanged
  --  4 - superseded
  --  5 - cessationOfOperation
  --  6 - certificateHold
  revocation_reason INTEGER DEFAULT NULL CHECK(revocation_reason >= 0)
);

-- create index for common queries
CREATE INDEX certificate_serial_number_idx ON certificate USING btree(serial_number);
CREATE INDEX certificate_fingerprint_md5_idx ON certificate USING btree(fingerprint_md5);
CREATE INDEX certificate_fingerprint_sha1_idx ON certificate USING btree(fingerprint_sha1);
CREATE INDEX certificate_state_idx ON certificate USING btree(state);
CREATE INDEX certificate_issuer_idx ON certificate USING btree(issuer);

-- table of x509 extensions
CREATE TABLE IF NOT EXISTS "extension" (

  -- primary key is the sha512 hash of (name+criticality+data)
  hash VARCHAR(128) PRIMARY KEY,

  -- name of the x509 extension
  name TEXT NOT NULL CHECK(name <> ''),

  -- criticality flag of the x509 extension
  criticality BOOLEAN NOT NULL DEFAULT False,

  -- base64 encoded data of the extension
  data TEXT NOT NULL CHECK(data <> '')
);
CREATE INDEX extension_name_idx ON extension USING btree(name);
