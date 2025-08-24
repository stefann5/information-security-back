-- 1. Admin korisnik
INSERT INTO "user" (id, username, password, name, surname, organization, role, authorities, user_type)
VALUES (1, 'admin', 'sifra', 'Marko', 'Petrović', 'TechCorp', 2, 'ADMIN,USER', 'Admin');

-- 2. Regularni korisnik
INSERT INTO "user" (id, username, password, name, surname, organization, role, authorities, user_type)
VALUES (2, 'john', 'sifra', 'John', 'Doe', 'MusicInc', 0, 'USER', 'User');

-- 3. Premium korisnik
INSERT INTO "user" (id, username, password, name, surname, organization, role, authorities, user_type)
VALUES (3, 'ana.milic', 'sifra', 'Ana', 'Milić', 'SoundWave', 0, 'USER,PREMIUM', 'PremiumUser');

-- 4. Moderator
INSERT INTO "user" (id, username, password, name, surname, organization, role, authorities, user_type)
VALUES (4, 'stefan.mod', 'sifra', 'Stefan', 'Nikolić', 'MusicPlatform', 1, 'MODERATOR,USER', 'Moderator');

-- 5. Test korisnik
INSERT INTO "user" (id, username, password, name, surname, organization, role, authorities, user_type)
VALUES (5, 'test.user', 'sifra', 'Test', 'Testović', 'TestOrg', 1, 'USER', 'User');