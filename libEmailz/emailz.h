//
//  emailz.h
//  libEmailz
//
//  Created by Curtis Jones on 2012.08.04.
//  Copyright (c) 2012 Curtis Jones. All rights reserved.
//

#ifndef libEmailz_emailz_h
#define libEmailz_emailz_h

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dispatch/dispatch.h>
#include <Block.h>
#include <Security/Security.h>

#define EMAILZ_MAX_LINE_SIZE    32000
#define EMAILZ_MAX_CMND_SIZE    50
#define EMAILZ_MAX_INDATA_SIZE  1048576
#define EMAILZ_SOCKET_TIMEOUT   120000

struct emailz_s;
struct emailz_mail_s;
struct emailz_socket_s;
struct emailz_listener_s;

//
// emailz_socket_state_t
//
typedef enum
{
	EMAILZ_SOCKET_STATE_OPEN=1,
	EMAILZ_SOCKET_STATE_CLOSE=2
} emailz_socket_state_t;

//
// emailz_smtp_command_t
//
typedef enum
{
	EMAILZ_SMTP_COMMAND_NONE     = 0,
	EMAILZ_SMTP_COMMAND_HELO     = (1 <<  1),
	EMAILZ_SMTP_COMMAND_EHLO     = (1 <<  2),
	EMAILZ_SMTP_COMMAND_MAIL     = (1 <<  3),
	EMAILZ_SMTP_COMMAND_RCPT     = (1 <<  4),
	EMAILZ_SMTP_COMMAND_DATA     = (1 <<  5),
	EMAILZ_SMTP_COMMAND_QUIT     = (1 <<  6),
	EMAILZ_SMTP_COMMAND_RSET     = (1 <<  7),
	EMAILZ_SMTP_COMMAND_NOOP     = (1 <<  8),
	EMAILZ_SMTP_COMMAND_HELP     = (1 <<  9),
	EMAILZ_SMTP_COMMAND_VRFY     = (1 << 10),
	EMAILZ_SMTP_COMMAND_AUTH     = (1 << 11),
	EMAILZ_SMTP_COMMAND_STARTTLS = (1 << 12)
} emailz_smtp_command_t;

//
// handlers
//
typedef void (^emailz_socket_handler_t)(struct emailz_s*, struct emailz_socket_s*, emailz_socket_state_t, void**);
typedef void (^emailz_smtp_handler_t)(struct emailz_s*, void*, emailz_smtp_command_t, unsigned char *arg);
typedef bool (^emailz_auth_handler_t)(struct emailz_s*, void*, char*, char*);
typedef void (^emailz_header_handler_t)(struct emailz_s*, void*, unsigned char *name, unsigned char *arg);
typedef void (^emailz_data_handler_t)(struct emailz_s*, void*, size_t datalen, const void *data, bool done);
typedef void (^emailz_accept_handler_t)(struct emailz_listener_s*, int socket, struct sockaddr_in);

//
// emailz_peerid_t
//
struct emailz_peerid_s
{
	uint32_t addr;
	uint16_t port;
};
typedef struct emailz_peerid_s *emailz_peerid_t;

//
// emailz_socket_t
//
struct emailz_socket_s
{
	/**
	 * daddy
	 */
	struct emailz_s *emailz;                   // daddy
	
	/**
	 * user settings
	 */
	void *context;                             // user context object
	emailz_socket_handler_t socket_handler;    // socket state handler
	emailz_smtp_handler_t smtp_handler;        // smtp command handler
	emailz_auth_handler_t auth_handler;        // smtp auth handler
	emailz_header_handler_t header_handler;    // email header handler
	emailz_data_handler_t data_handler;        // email data handler
	uint64_t smtp_handler_mask;                // mask for smtp commands
	
	/**
	 * gcd
	 */
	dispatch_io_t channel;                     // dispatch channel for socket
	dispatch_queue_t queue;                    // socket read queue
	dispatch_data_t indata;                    // unprocessed (unencrypted) incoming data
	dispatch_data_t tmpdata;                   // unprocessed (encrypted) incoming data
	
	/**
	 * connection stats
	 */
	uint64_t inbytes;                          // number of received bytes
	uint64_t outbytes;                         // number of sent bytes
	uint64_t connect_time;                     // time at which accept() occurred
	uint64_t last_read_time;                   // time at which last read() occurred
	
	/**
	 * read state
	 */
	emailz_smtp_command_t state;               // the last smtp command handled on this socket
	uint64_t email_size;                       // used to enforce EMAILZ_MAX_INDATA_SIZE
	unsigned char line[EMAILZ_MAX_LINE_SIZE];  //
	unsigned char cmnd[EMAILZ_MAX_CMND_SIZE];  //
	size_t lineoff;                            //
	size_t linelen;                            //
	size_t cmndlen;                            //
	
	/**
	 * socket stuff
	 */
	int socketfd;                              // socket descriptor
	struct sockaddr_in addr;                   // socket address
	uint16_t port;                             // remote port number
	char addrstr[46];                          // ipv4/6 address string
	bool stop;                                 // stop the presses
	
	/**
	 * crypto
	 */
	SSLContextRef sslcontext;                  //
	struct emailz_peerid_s peerid;             // ip:port
	bool is_handshaking;                       //
	bool is_secure;                            // connection is secure
	CFArrayRef identity;                       // ssl root certificate
	
	/**
	 * record
	 */
	char record_path[1000];                    // path to socket record file
	char record_name[100];                     // record file name
	FILE *record;                              // where we record the incoming socket data
	
};
typedef struct emailz_socket_s *emailz_socket_t;

//
// emailz_listener_t
//
struct emailz_listener_s
{
	/**
	 * user settings
	 */
	emailz_accept_handler_t accept_handler;    // accept handler
	
	/**
	 * gcd
	 */
	dispatch_queue_t queue;                    // dispatch queue
	dispatch_source_t source;                  // dispatch source
	
	/**
	 * socket stuff
	 */
	int socketfd;                              // socket descriptor
	struct sockaddr_in addr;                   // listen address
	uint16_t port;                             // listen port
	
	/**
	 * listener stats
	 */
	uint64_t inconns;                          // number of accepted connections
	
};
typedef struct emailz_listener_s *emailz_listener_t;

//
// emailz_t
//
struct emailz_s
{
	/**
	 * user settings
	 */
	emailz_socket_handler_t socket_handler;    // socket state handler
	bool socket_record;                        // enable socket recording?
	char record_base[1000];                    // recording base directory
	
	/**
	 * listeners
	 */
	emailz_listener_t smtp_v4_listener;        // 25
	emailz_listener_t smtp_tls_v4_listener;    // 587
	
	/**
	 * gcd
	 */
	dispatch_queue_t listener_queue;           //
	dispatch_queue_t socket_queue;             //
	
	/**
	 * crypto
	 */
	CFArrayRef identity;                       // ssl root certificate
	
	/**
	 * stats
	 */
	uint64_t bytes_rcvd;                       //
	uint64_t bytes_sent;                       //
	uint64_t sockets_open;                     //
	uint64_t sockets_total;                    //
	
};
typedef struct emailz_s *emailz_t;





/**
 *
 */
emailz_t emailz_create ();
void emailz_destroy (emailz_t);
bool emailz_start (emailz_t);
bool emailz_stop (emailz_t);
void emailz_set_socket_handler (emailz_t, emailz_socket_handler_t);

/**
 *
 */
void emailz_socket_set_smtp_handler (emailz_socket_t, emailz_smtp_handler_t, uint64_t);
void emailz_socket_set_header_handler (emailz_socket_t, emailz_header_handler_t);
void emailz_socket_set_data_handler (emailz_socket_t, emailz_data_handler_t);

/**
 *
 */
uint64_t emailz_current_time_millis ();

#endif /* libEmailz_emailz_h */
