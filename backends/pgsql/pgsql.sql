CREATE TABLE IF NOT EXISTS "certificate" (
  certificate_id SERIAL PRIMARY KEY,

  -- Note: RFC 3280 (4.1.2.2  Serial number) states the serial number
  -- must be:
  --  * unique
  --  * non-negative integer
  --  * up to 20 octets (up to 2**160)
  --  * not longer than 20 octets
  --
  -- so BIGINT is to small, we use TEXT instead to hold the hex string
  --
  -- serial_number is NULL for certificates that are
  -- not issued yet, therefore it can't be used as primary key
  serial_number TEXT UNIQUE CHECK(serial_number <> '')

  -- set to NULL when certificate was not issued yet
  -- (csr submitted but pending)
  start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  end_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,

  -- subject of certificate
  -- it is NOT unique as it may occur for current and revoked certificates
  subject TEXT NOT NULL CHECK(subject <> ''),

  -- store fingerprints for subject data
  -- as serial_number and certificate content should be
  -- unique, enforce constraints
  -- fingerprint_* is not set (NULL) for certificates not
  -- issued yet
  fingerprint_md5 VARCHAR(32) UNIQUE DEFAULT NULL CHECK(fingerprint_md5 <> ''),
  fingerprint_sha1 VARCHAR(40) UNIQUE DEFAULT NULL CHECK(fingerprint_sha1 <> ''),

  -- store certificate purpose
  -- NULL for pending certificates
  purpose_ssl_client BOOLEAN DEFAULT NULL,
  purpose_ssl_client_ca BOOLEAN DEFAULT NULL,
  purpose_ssl_server BOOLEAN DEFAULT NULL,
  purpose_ssl_server_ca BOOLEAN DEFAULT NULL,
  purpose_netscape_ssl_server BOOLEAN DEFAULT NULL,
  purpose_netscape_ssl_server_ca BOOLEAN DEFAULT NULL,
  purpose_smime_signing BOOLEAN DEFAULT NULL,
  purpose_smime_signing_ca BOOLEAN DEFAULT NULL,
  purpose_smime_encryption BOOLEAN DEFAULT NULL,
  purpose_smime_encryption_ca BOOLEAN DEFAULT NULL,
  purpose_crl_signing BOOLEAN DEFAULT NULL,
  purpose_crl_signing_ca BOOLEAN DEFAULT NULL,
  purpose_any_purpose BOOLEAN DEFAULT NULL,
  purpose_any_purpose_ca BOOLEAN DEFAULT NULL,
  purpose_ocsp_helper BOOLEAN DEFAULT NULL,
  purpose_ocsp_helper_ca BOOLEAN DEFAULT NULL,
  purpose_timestamp_signing BOOLEAN DEFAULT NULL,
  purpose_timestamp_signing_ca BOOLEAN DEFAULT NULL,

  -- certificate holds the base64 encoded public key
  -- it is NULL for pending certificates
  certificate TEXT UNIQUE CHECK(certificate <> ''),

  -- store original signing request, can be NULL if
  -- original csr is missing.
  -- Note: This is NOT unique 
  signing_request TEXT UNIQUE CHECK(signing_request <> ''),

  -- state is the current state of the certificate
  -- possible values are
  --  0 - pending: CSR submitted but not issued yet
  --  1 - issued: CSR has been processed, certificate has been issued
  --  2 - revoked: certificate has been revoked
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

