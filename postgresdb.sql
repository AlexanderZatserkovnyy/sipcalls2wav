/* CREATE ROLE dbworker LOGIN PASSWORD 'MYPASSWORD';

CREATE DATABASE voiplog OWNER dbworker ENCODING 'UTF-8';

\c voiplog; */

CREATE TABLE IF NOT EXISTS cdr (
  clid character varying(80) DEFAULT '' PRIMARY KEY,
  calldate timestamp with time zone DEFAULT now() NOT NULL,
  src character varying(255) DEFAULT '' NOT NULL,
  dst character varying(255) DEFAULT '' NOT NULL,
  dcontext character varying(80) DEFAULT '' NOT NULL,
  channel character varying(80) DEFAULT '' NOT NULL,
  dstchannel character varying(80) DEFAULT '' NOT NULL,
  lastapp character varying(80) DEFAULT '' NOT NULL,
  lastdata character varying(80) DEFAULT '' NOT NULL,
  duration bigint DEFAULT 0::bigint NOT NULL,
  billsec bigint DEFAULT 0::bigint NOT NULL,
  disposition character varying(45) DEFAULT '' NOT NULL,
  amaflags bigint DEFAULT 0::bigint NOT NULL,
  accountcode character varying(20) DEFAULT '' NOT NULL,
  uniqueid character varying(32) DEFAULT '' NOT NULL,
  userfield character varying(255) DEFAULT '' NOT NULL,
  pcap boolean DEFAULT 'FALSE' NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id serial PRIMARY KEY,
  clid character varying(80) NOT NULL,
  ssrc character varying(80) NOT NULL,
  codec character varying(4) DEFAULT '' NOT NULL,
  f_opened timestamp with time zone default now() NOT NULL,
  f_closed timestamp with time zone default now() NOT NULL,
  filename character varying(255) DEFAULT '' NOT NULL 
);

CREATE TABLE IF NOT EXISTS requests (
  id serial PRIMARY KEY,
  abonent_id character varying(80) NOT NULL,
  int_begin timestamp with time zone NOT NULL,
  int_end   timestamp with time zone default now() NOT NULL
);

/* INSERT INTO requests (abonent_id,int_begin,int_end) VALUES ('sip:82221113333@10.1.1.1','2017-09-01 12:45+10', '2017-09-21 01:00+10') */
/*about time intervals: 2017-09-01 12:45+10 , +10 - TIME ZONE, [ - including boundary, ( - excluding , infinity can be used as value
*/

CREATE INDEX IF NOT EXISTS cdr_clid ON cdr (clid);
CREATE INDEX IF NOT EXISTS requests_ab ON requests (abonent_id,int_begin,int_end);


/* disposition: ANSWERED, FAILED, BUSY, NO ANSWER */

