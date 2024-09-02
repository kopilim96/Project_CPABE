CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    common_name TEXT,
    country TEXT,
    state TEXT,
    locality TEXT,
    organization TEXT,
    organizational_unit TEXT,
    email TEXT,
    ca_approve BOOLEAN default 0,
    is_admin BOOLEAN DEFAULT 0,
    is_ca BOOLEAN DEFAULT 0,
    is_doctor BOOLEAN DEFAULT 0,
    is_patient BOOLEAN DEFAULT 0
);

-- ca_approve default 0, 1 is approve, 2 is deny

-- Insert sample data, password 123
INSERT OR IGNORE INTO users (username, password, ca_approve, is_admin, is_ca, is_doctor, is_patient)
VALUES 
('admin', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 1, 1, 0, 0, 0),
('doctor1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 0, 0, 0, 1, 0), 
('patient1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 0, 0, 0, 0, 1),
('ca1', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',1, 0, 1, 0, 0);
