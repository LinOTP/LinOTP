/*!
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
 *
 *   This file is part of LinOTP userid resolvers.
 *
 *   This program is free software: you can redistribute it and/or
 *   modify it under the terms of the GNU Affero General Public
 *   License, version 3, as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the
 *              GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.lsexperts.de
 *
 */
DROP TABLE "LinOtpUserS";
CREATE TABLE "LinOtpUserS"(id int, "userName" varchar(20), "givenName" varchar(20), surname varchar(20), password varchar(100), "sALT" varchar(30), email varchar(100));
INSERT INTO "LinOtpUserS" VALUES(1,'user1','Benutzer','Eins','pr1tkg5AOplio','pr','user1@testdomain.de');
INSERT INTO "LinOtpUserS" VALUES(2,'user2','Benutzer','Zwo','F6Z11ZD5ZUfxg','F6','user2@testdomain.de');
INSERT INTO "LinOtpUserS" VALUES(3,'user_3','Pro%ent','Drei','abgOeLfPimXQo','ab','user3@testdomain.de');
INSERT INTO "LinOtpUserS" VALUES(4,'userx3','Prosesesent','Dreieinhalb','abgOeLfPimXQo','ab','user3@testdomain.de');
