//
//  emailz.c
//  libEmailz
//
//  Created by Curtis Jones on 2012.08.04.
//  Copyright (c) 2012 Curtis Jones. All rights reserved.
//

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <Block.h>
#include "emailz.h"
#include "logger.h"

#define XLOG(...) {LOGX(__VA_ARGS__);}

static void emailz_handle_accept (emailz_t, emailz_listener_t, int, struct sockaddr_in);

static emailz_socket_t emailz_socket_create ();
static bool emailz_socket_start (emailz_socket_t, bool);
static bool emailz_socket_stop (emailz_socket_t);
static void emailz_socket_handle_read (emailz_socket_t, bool, dispatch_data_t);
static void emailz_socket_setup_ssl (emailz_socket_t);
static bool emailz_socket_read_line (emailz_socket_t);
static void emailz_socket_read_command (emailz_socket_t);
static void emailz_socket_handle_write (emailz_socket_t, char*, ssize_t, dispatch_io_handler_t);
static void emailz_socket_record (emailz_socket_t, dispatch_data_t);
static bool emailz_socket_record_open (emailz_socket_t);
static void emailz_socket_record_close (emailz_socket_t);

static emailz_listener_t emailz_listener_create (emailz_t, uint16_t);
static bool emailz_listener_start (emailz_listener_t);
static void emailz_listener_set_accept_handler (emailz_listener_t, emailz_accept_handler_t);

static OSStatus emailz_sslsocket_write (SSLConnectionRef connection, const void *buffer, size_t *bufferlen);
static OSStatus emailz_sslsocket_read (SSLConnectionRef connection, void *data, size_t *datalen);

static void emailz_addrstr (void*, int, char*);
static char* emailz_print_number (char*, uint64_t, int);
static void* NewBase64Decode (const char*, size_t, char*, size_t*);
static char* NewBase64Encode (const void*, size_t, bool, size_t*);
static void hexdump (uint8_t*, int);





#pragma mark - emailz - public

/**
 *
 *
 */
emailz_t
emailz_create ()
{
	emailz_t emailz = malloc(sizeof(struct emailz_s));
	memset(emailz, 0, sizeof(struct emailz_s));
	return emailz;
}

/**
 *
 *
 */
void
emailz_destroy (emailz_t emailz)
{
	
	// TODO: implement me
	
}

/**
 *
 *
 */
bool
emailz_start (emailz_t emailz)
{
	emailz->listener_queue = dispatch_queue_create("emailz.listener-queue", DISPATCH_QUEUE_SERIAL);
	emailz->socket_queue = dispatch_queue_create("emailz.socket-queue", DISPATCH_QUEUE_CONCURRENT);
	
	// ssl root certificate
	{
		OSStatus oserr;
		SecIdentityRef identity;
		CFArrayRef identities;
		
		{
			CFDataRef keydata = NULL;
			CFArrayRef items = NULL;
			CFDictionaryRef options;
			CFStringRef password = CFSTR("corvette");
			
			options = CFDictionaryCreate(NULL, (const void **)&kSecImportExportPassphrase, (const void **)&password, 1, NULL, NULL);
			
			{
#warning Replace this with the path to your self-signed private key
				int keyfd = open("/path/to/your/PrivateKey.p12", O_RDONLY);
				off_t keylen = lseek(keyfd, 0, SEEK_END);
				void *content = mmap(NULL, keylen, PROT_READ, MAP_PRIVATE, keyfd, 0);
				
				if (NULL == (keydata = CFDataCreate(NULL, content, keylen))) {
					printf("%s.. failed to CFDataCreate()\n", __PRETTY_FUNCTION__);
					return false;
				}
				
				munmap(content, keylen);
				close(keyfd);
			}
			
			if (noErr != (oserr = SecPKCS12Import(keydata, options, &items))) {
				printf("%s.. failed to SecPKCS12Import(), %d\n", __PRETTY_FUNCTION__, oserr);
				return false;
			}
			
			CFDictionaryRef import = CFArrayGetValueAtIndex(items, 0);
			identity = (SecIdentityRef)CFDictionaryGetValue(import, CFSTR("identity"));
			
			if (NULL == (identities = CFArrayCreate(NULL, (const void **)&identity, 1, NULL))) {
				printf("%s.. failed to CFArrayCreate()\n", __PRETTY_FUNCTION__);
				return false;
			}
			
			// TODO: releasing one or more of these causes problems with the identities array
			
			//CFRelease(import);
			//CFRelease(items);
			//CFRelease(options);
			//CFRelease(keydata);
		}
		
		emailz->identity = identities;
	}
	
	// SMTP IPv4
	{
		emailz_accept_handler_t accept_handler = ^ (emailz_listener_t _listener, int _socket, struct sockaddr_in _addr) {
			emailz_handle_accept(emailz, _listener, _socket, _addr);
		};
		
		emailz->smtp_v4_listener = emailz_listener_create(emailz, 10025);
		emailz_listener_set_accept_handler(emailz->smtp_v4_listener, accept_handler);
		emailz_listener_start(emailz->smtp_v4_listener);
	}
	
	// ESMTP IPv4
	{
		emailz_accept_handler_t accept_handler = ^ (emailz_listener_t _listener, int _socket, struct sockaddr_in _addr) {
			emailz_handle_accept(emailz, _listener, _socket, _addr);
		};
		
		emailz->smtp_tls_v4_listener = emailz_listener_create(emailz, 10587);
		emailz_listener_set_accept_handler(emailz->smtp_tls_v4_listener, accept_handler);
		emailz_listener_start(emailz->smtp_tls_v4_listener);
	}
	
	return true;
}

/**
 *
 *
 */
bool
emailz_stop (emailz_t emailz)
{
	
	// TODO: implement me
	
	return true;
}

/**
 *
 *
 */
void
emailz_set_socket_handler (emailz_t emailz, emailz_socket_handler_t handler)
{
	if (!emailz)
		return;
	
	if (emailz->socket_handler) {
		Block_release(emailz->socket_handler);
		emailz->socket_handler = NULL;
	}
	
	if (handler)
		emailz->socket_handler = (emailz_socket_handler_t)Block_copy(handler);
}

/**
 *
 *
 */
void
emailz_record_enable (emailz_t emailz, bool enable, char *base)
{
	if (!emailz)
		return;
	
	emailz->socket_record = enable;
	
	if (strlen(base) >= sizeof(emailz->record_base)) {
		printf("%s.. base dir is longer than we support\n", __PRETTY_FUNCTION__);
		return;
	}
	
	strcpy(emailz->record_base, base);
}





#pragma mark - emailz - private

/**
 *
 *
 */
void
emailz_handle_accept (emailz_t emailz, emailz_listener_t listener, int socketfd, struct sockaddr_in addr)
{
	if (!emailz)
		return;
	
	if (!listener)
		return;
	
	emailz_socket_t socket = emailz_socket_create(emailz);
	socket->socketfd = socketfd;
	socket->addr = addr;
	socket->port = addr.sin_port;
	socket->socket_handler = emailz->socket_handler;
	socket->identity = emailz->identity;
	socket->peerid.addr = addr.sin_addr.s_addr;
	socket->peerid.port = addr.sin_port;
	
	emailz_addrstr(&addr.sin_addr, addr.sin_family, socket->addrstr);
	
	emailz->sockets_open += 1;
	emailz->sockets_total += 1;
	
	XLOG("[%s:%hu] new connection", socket->addrstr, socket->port);
	
	emailz_socket_start(socket, emailz->socket_record);
	emailz_socket_handle_write(socket, "220 mail.spamass.net ESMTP\r\n", -1, NULL);
}





#pragma mark - socket - private

/**
 *
 *
 */
emailz_socket_t
emailz_socket_create (emailz_t emailz)
{
	emailz_socket_t socket = malloc(sizeof(struct emailz_socket_s));
	memset(socket, 0, sizeof(struct emailz_socket_s));
	
	socket->emailz = emailz;
	socket->queue = emailz->socket_queue;
	socket->connect_time = emailz_current_time_millis();
	socket->stop = false;
	socket->last_read_time = emailz_current_time_millis();
	
	return socket;
}

/**
 *
 *
 */
void
emailz_socket_destroy (emailz_socket_t socket)
{
	if (!socket)
		return;
	
	if (socket->channel)
		dispatch_release(socket->channel);
	
	if (socket->sslcontext) {
		SSLDisposeContext(socket->sslcontext);
		socket->sslcontext = NULL;
	}
	
	socket->socket_handler = NULL;
	
	if (socket->smtp_handler) {
		Block_release(socket->smtp_handler);
		socket->smtp_handler = NULL;
	}
	
	if (socket->header_handler) {
		Block_release(socket->header_handler);
		socket->header_handler = NULL;
	}
	
	if (socket->data_handler) {
		Block_release(socket->data_handler);
		socket->data_handler = NULL;
	}
	
	if (socket->indata) {
		dispatch_release(socket->indata);
		socket->indata = NULL;
	}
	
	if (socket->tmpdata) {
		dispatch_release(socket->tmpdata);
		socket->tmpdata = NULL;
	}
	
	socket->identity = NULL;
	
	free(socket);
}

/**
 *
 *
 */
bool
emailz_socket_start (emailz_socket_t socket, bool record)
{
	if (!socket)
		return false;
	
	if (!socket->queue)
		return false;
	
	// disable nagle's algorithm which is a good thing to do for ssl/tls
	{
		int nodelay = 1;
		
		if (0 != setsockopt(socket->socketfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay))) {
			XLOG("[%s:%hu] failed to setsockopt(TCP_NODELAY), %s", socket->addrstr, socket->port, strerror(errno));
			return false;
		}
	}
	
	// socket name
	{
		char *name_ptr = socket->record_name;
		time_t clock = socket->connect_time / 1000;
		struct tm *date = gmtime(&clock);
		uint32_t addr = ntohl(socket->addr.sin_addr.s_addr);
		
		// yyyymmddhhmmss-xxx-xxx.xxx.xxx.xxx-xxxxx.socket
		{
			// yyyymmddhhmmssmmm
			name_ptr = emailz_print_number(name_ptr, 1900+date->tm_year, 4);
			name_ptr = emailz_print_number(name_ptr,    1+date->tm_mon,  2);
			name_ptr = emailz_print_number(name_ptr,      date->tm_mday, 2);
			name_ptr = emailz_print_number(name_ptr,    1+date->tm_hour, 2);
			name_ptr = emailz_print_number(name_ptr,      date->tm_min,  2);
			name_ptr = emailz_print_number(name_ptr,      date->tm_sec,  2);
			name_ptr = emailz_print_number(name_ptr, (socket->connect_time%1000), 3);
			
			// ip address
			*name_ptr = '-'; name_ptr += 1;
			name_ptr = emailz_print_number(name_ptr, 0xFF & (addr >> 24), 3);
			*name_ptr = '.'; name_ptr += 1;
			name_ptr = emailz_print_number(name_ptr, 0xFF & (addr >> 16), 3);
			*name_ptr = '.'; name_ptr += 1;
			name_ptr = emailz_print_number(name_ptr, 0xFF & (addr >>  8), 3);
			*name_ptr = '.'; name_ptr += 1;
			name_ptr = emailz_print_number(name_ptr, 0xFF & (addr      ), 3);
			
			// port
			*name_ptr = '-';
			name_ptr += 1;
			name_ptr = emailz_print_number(name_ptr, socket->port, 5);
		}
	}
	
	if (socket->socket_handler)
		socket->socket_handler(socket->emailz, socket, EMAILZ_SOCKET_STATE_OPEN, &socket->context);
	
	if (record) {
		if (false == emailz_socket_record_open(socket)) {
			XLOG("[%s:%hu] failed to emailz_socket_record_open()", socket->addrstr, socket->port);
		}
	}
	
	socket->indata = dispatch_data_create(NULL, 0, NULL, NULL);
	socket->tmpdata = dispatch_data_create(NULL, 0, NULL, NULL);
	socket->channel = dispatch_io_create(DISPATCH_IO_STREAM, socket->socketfd, socket->queue, ^ (int error) {
		//XLOG("[%s:%hu] socket closing [bytes_in=%llu, bytes_out=%llu, error=%d]", socket->addrstr, socket->port, socket->inbytes, socket->outbytes, error);
		
		if (socket->socket_handler)
			socket->socket_handler(socket->emailz, socket, EMAILZ_SOCKET_STATE_CLOSE, &socket->context);
		
		socket->emailz->sockets_open -= 1;
		
		emailz_socket_destroy(socket);
	});
	
	dispatch_io_set_low_water(socket->channel, 1);
	dispatch_io_set_interval(socket->channel, 10000000000ull, DISPATCH_IO_STRICT_INTERVAL);
	
	dispatch_io_read(socket->channel, 0, SIZE_MAX, socket->queue, ^ (bool done, dispatch_data_t data, int error) {
		if (socket->stop)
			return;
		
		if (data) {
			size_t size = dispatch_data_get_size(data);
			
			socket->last_read_time = emailz_current_time_millis();
			socket->inbytes += size;
			socket->emailz->bytes_rcvd += size;
			
			//XLOG("[%s:%hu] received %lu bytes [bytes_in=%llu, bytes_out=%llu]", socket->addrstr, socket->port, dispatch_data_get_size(data), socket->inbytes, socket->outbytes);
			
			emailz_socket_handle_read(socket, done, data);
		}
		
		if (done || error)
			emailz_socket_stop(socket);
		else if (socket->last_read_time < emailz_current_time_millis() - EMAILZ_SOCKET_TIMEOUT)
			emailz_socket_stop(socket);
	});
	
	return true;
}

/**
 *
 *
 */
bool
emailz_socket_stop (emailz_socket_t socket)
{
	if (!socket)
		return false;
	
	socket->stop = true;
	
	if (socket->socketfd) {
		if (socket->sslcontext && socket->channel)
			SSLClose(socket->sslcontext);
		
		if (socket->channel)
			dispatch_io_close(socket->channel, DISPATCH_IO_STOP);
		
		close(socket->socketfd);
		socket->socketfd = 0;
	}
	
	emailz_socket_record_close(socket);
	
	return true;
}

/**
 *
 *
 */
void
emailz_socket_handle_read (emailz_socket_t socket, bool done, dispatch_data_t data)
{
	if (!socket)
		return;
	
	// if we have an ssl connection (or we're in the process of doing an ssl handshake), read and
	// decrypt data (in the former case) and continue the handshake process (in the latter case).
	if (socket->sslcontext) {
		OSStatus oserr;
		unsigned char buffer[1000];
		size_t processed = 0;
		
		dispatch_data_t tmpdata = socket->tmpdata;
		socket->tmpdata = dispatch_data_create_concat(tmpdata, data);
		dispatch_release(tmpdata);
		
		if (socket->is_handshaking) {
			if (errSSLWouldBlock == (oserr = SSLHandshake(socket->sslcontext)))
				return;
			else if (oserr) {
				XLOG("[%s:%hu] failed to handshake [%d]", socket->addrstr, socket->port, oserr);
				emailz_socket_stop(socket);
				return;
			}
			else {
				XLOG("[%s:%hu] ssl connection established", socket->addrstr, socket->port);
				socket->is_handshaking = false;
				socket->is_secure = true;
			}
		}
		
		while (1) {
			oserr = SSLRead(socket->sslcontext, buffer, 1000, &processed);
			
			if (oserr && oserr == errSSLClosedGraceful) {
				printf("%s.. ssl connection closed gracefully\n", __PRETTY_FUNCTION__);
				emailz_socket_stop(socket);
				break;
			}
			else if (oserr && oserr != errSSLWouldBlock) {
				printf("%s.. failed to SSLRead(), %s [%d]\n", __PRETTY_FUNCTION__, strerror(oserr), oserr);
				emailz_socket_stop(socket);
				break;
			}
			else if (!processed)
				break;
			else {
				dispatch_data_t _data = dispatch_data_create(buffer, processed, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
				dispatch_data_t _indata = socket->indata;
				socket->indata = dispatch_data_create_concat(_indata, _data);
				emailz_socket_record(socket, _data);
				dispatch_release(_data);
				dispatch_release(_indata);
			}
		}
	}
	
	// we're not using ssl so just read data and append it to our read buffer
	else {
		emailz_socket_record(socket, data);
		dispatch_data_t indata = socket->indata;
		socket->indata = dispatch_data_create_concat(indata, data);
		dispatch_release(indata);
	}
	
	// while our in buffer isn't empty and while we're able to read a complete line (or in the case of
	// not being able to find a newline, the amount of available data exceeds our maximum line length)
	// process the line.
	//
	// each line is either an smtp command or if we're in a "DATA" state, it's part of the data
	// segment of an email (or the "." terminating the data segment).
	//
	while (0 != dispatch_data_get_size(socket->indata) && emailz_socket_read_line(socket)) {
		//XLOG("[%s:%hu] %s", socket->addrstr, socket->port, socket->line);
		
		// we're reading the data segment of the email. if the line is simply a "." then we've reached
		// the end of the data segment. otherwise, handle the email data. in both cases we call the
		// data_handler and let them know what's going on. we don't actually retain any of this data.
		if (EMAILZ_SMTP_COMMAND_DATA == socket->state) {
			if (socket->linelen == 3 && socket->line[0] == '.' && socket->line[1] == '\r' && socket->line[2] == '\n')  {
				if (socket->data_handler)
					socket->data_handler(socket->emailz, socket->context, 0, NULL, true);
				socket->state = EMAILZ_SMTP_COMMAND_NONE;
				emailz_socket_handle_write(socket, "250 AAA14672 Message accepted for delivery\r\n", -1, NULL);
			}
			else {
				socket->email_size += socket->linelen;
				
				if (socket->data_handler)
					socket->data_handler(socket->emailz, socket->context, socket->linelen, socket->line, (socket->email_size > EMAILZ_MAX_INDATA_SIZE));
				
				if (socket->email_size > EMAILZ_MAX_INDATA_SIZE) {
					emailz_socket_stop(socket);
					break;
				}
			}
		}
		
		// we're not in the data segment, so parse the command off the front of the line and see how we
		// should best handle it.
		else {
			emailz_socket_read_command(socket);
			
			// we weren't able to parse a command
			if (socket->cmndlen == 0)
				break;
			
			emailz_smtp_command_t command = EMAILZ_SMTP_COMMAND_NONE;
			
			// figure out which command we've received and give us a more mangeable data type
			{
				if (0 == strncmp((char *)socket->cmnd, "HELO", 4))
					command = EMAILZ_SMTP_COMMAND_HELO;
				else if (0 == strncmp((char *)socket->cmnd, "EHLO", 4))
					command = EMAILZ_SMTP_COMMAND_EHLO;
				else if (0 == strncmp((char *)socket->cmnd, "MAIL", 4))
					command = EMAILZ_SMTP_COMMAND_MAIL;
				else if (0 == strncmp((char *)socket->cmnd, "RCPT", 4))
					command = EMAILZ_SMTP_COMMAND_RCPT;
				else if (0 == strncmp((char *)socket->cmnd, "DATA", 4))
					command = EMAILZ_SMTP_COMMAND_DATA;
				else if (0 == strncmp((char *)socket->cmnd, "QUIT", 4))
					command = EMAILZ_SMTP_COMMAND_QUIT;
				else if (0 == strncmp((char *)socket->cmnd, "RSET", 4))
					command = EMAILZ_SMTP_COMMAND_RSET;
				else if (0 == strncmp((char *)socket->cmnd, "NOOP", 4))
					command = EMAILZ_SMTP_COMMAND_NOOP;
				else if (0 == strncmp((char *)socket->cmnd, "HELP", 4))
					command = EMAILZ_SMTP_COMMAND_HELP;
				else if (0 == strncmp((char *)socket->cmnd, "VRFY", 4))
					command = EMAILZ_SMTP_COMMAND_VRFY;
				else if (0 == strncmp((char *)socket->cmnd, "AUTH", 4))
					command = EMAILZ_SMTP_COMMAND_AUTH;
				else if (0 == strncmp((char *)socket->cmnd, "STARTTLS", 8))
					command = EMAILZ_SMTP_COMMAND_STARTTLS;
				else
					XLOG("[%s:%hu] unsupported command, %s", socket->addrstr, socket->port, socket->cmnd);
			}
			
			// note the socket state - that is, which command we're currently processing
			socket->state = command;
			
			// if there's an smtp_handler, and if this command is part of the mask set for the handler,
			// then call the callback so that they know what's going on.
			if (socket->smtp_handler && (command & socket->smtp_handler_mask))
				socket->smtp_handler(socket->emailz, socket->context, command, socket->line+socket->lineoff);
			
			// respond to the command. in most cases this is just an "ok" message. if the caller dares to
			// try to start an ssl connection, then fire up our ssl code and get that going. if we don't
			// support the command, tell the client.
			switch (command) {
				case EMAILZ_SMTP_COMMAND_HELO:
					emailz_socket_handle_write(socket, "250 mail.spamass.net\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_EHLO:
					if (!socket->is_secure)
						emailz_socket_handle_write(socket, "250-mail.spamass.net in the house\r\n250-SIZE 12345678\r\n250-8BITMIME\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n", -1, NULL);
					else
						emailz_socket_handle_write(socket, "250-mail.spamass.net in the house\r\n250-SIZE 12345678\r\n250-8BITMIME\r\n250-AUTH PLAIN\r\n250 ENHANCEDSTATUSCODES\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_MAIL:
					emailz_socket_handle_write(socket, "250 Ok\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_RCPT:
					emailz_socket_handle_write(socket, "250 Recipient ok\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_DATA:
					socket->email_size = 0;
					emailz_socket_handle_write(socket, "354 Enter mail, end with \".\" on a line by itself\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_QUIT:
					emailz_socket_handle_write(socket, "221 closing connection\r\n", -1, ^(bool done, dispatch_data_t data, int error) { emailz_socket_stop(socket); });
					break;
					
				case EMAILZ_SMTP_COMMAND_RSET:
					emailz_socket_handle_write(socket, "250 Ok\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_NOOP:
					emailz_socket_handle_write(socket, "250 Ok\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_HELP:
					emailz_socket_handle_write(socket, "214-2.3.0 Available commands:\r\n214-2.3.0\r\n214-2.3.0 HELO, EHLO, MAIL FROM, RCPT TO, DATA\r\n214-2.3.0 QUIT, RSET, NOOP, HELP, VRFY, STARTTLS\r\n214 2.3.0\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_VRFY:
					emailz_socket_handle_write(socket, "252 2.1.5 It doesn't hurt to try\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_AUTH:
					if (socket->is_secure) {
						bool isauth = false;
						
						if (0 == strncmp((char *)socket->line, "AUTH PLAIN ", 11) && socket->linelen > 13 && socket->linelen < 150) {
							char decodeBuf[150] = { 0 };
							size_t decodeLen = 150;
							
							NewBase64Decode(((char *)socket->line)+11, socket->linelen-13, decodeBuf, &decodeLen);
							//hexdump((uint8_t *)decodeBuf, (int)decodeLen);
							
							if (decodeLen >= 3) {
								unsigned long userLen = strlen(((char *)decodeBuf)+1);
								XLOG("[%s:%hu] user='%s', pass='%s'", socket->addrstr, socket->port, ((char *)decodeBuf)+1, ((char *)decodeBuf)+1+userLen+1);
								isauth = !socket->auth_handler ? true : socket->auth_handler(socket->emailz, socket->context, ((char *)decodeBuf)+1, ((char *)decodeBuf)+1+userLen+1);
							}
						}
						
						if (isauth)
							emailz_socket_handle_write(socket, "235 You are good to go\r\n", -1, NULL);
						else
							emailz_socket_handle_write(socket, "535 Authentication failed; restarting authentication process\r\n", -1, NULL);
					}
					else
						emailz_socket_handle_write(socket, "502 Unsupported command\r\n", -1, NULL);
					break;
					
				case EMAILZ_SMTP_COMMAND_STARTTLS:
					if (!socket->is_secure) {
						emailz_socket_handle_write(socket, "220 Ready to start TLS\r\n", -1, NULL);
						emailz_socket_setup_ssl(socket);
					}
					else
						emailz_socket_handle_write(socket, "502 Unsupported command\r\n", -1, NULL);
					break;
					
				default:
					XLOG("[%s:%hu] unsupported command, %d", socket->addrstr, socket->port, command);
					emailz_socket_handle_write(socket, "502 Unsupported command\r\n", -1, NULL);
					break;
			}
		}
	}
}

/**
 *
 *
 */
void
emailz_socket_setup_ssl (emailz_socket_t socket)
{
	OSStatus oserr;
	
	if (noErr != (oserr = SSLNewContext(true, &socket->sslcontext))) {
		XLOG("[%s:%hu] failed to SSLNewContext(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetIOFuncs(socket->sslcontext, emailz_sslsocket_read, emailz_sslsocket_write))) {
		XLOG("[%s:%hu] failed to SSLSetIOFuncs(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetProtocolVersionEnabled(socket->sslcontext, kSSLProtocolAll, true))) {
		XLOG("[%s:%hu] failed to SSLSetProtocolVersionEnabled(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetConnection(socket->sslcontext, socket))) {
		XLOG("[%s:%hu] failed to SSLSetConnection(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetAllowsExpiredCerts(socket->sslcontext, true))) {
		XLOG("[%s:%hu] failed to SSLSetAllowExpiredCerts(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetEnableCertVerify(socket->sslcontext, false))) {
		XLOG("[%s:%hu] failed to SSLSetEnableCertVerify(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetAllowsAnyRoot(socket->sslcontext, true))) {
		XLOG("[%s:%hu] failed to SSLSetAllowsAnyRoot(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetCertificate(socket->sslcontext, socket->identity))) {
		XLOG("[%s:%hu] failed to SSLSetCertificate(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	if (noErr != (oserr = SSLSetPeerID(socket->sslcontext, &socket->peerid, sizeof(socket->sslcontext)))) {
		XLOG("[%s:%hu] failed to SSLSetPeerID(), %d", socket->addrstr, socket->port, oserr);
		return;
	}
	
	socket->is_handshaking = true;
	
	if ((oserr = SSLHandshake(socket->sslcontext)) && errSSLWouldBlock != oserr) {
		XLOG("[%s:%hu] failed to SSLHandshake(), %d", socket->addrstr, socket->port, oserr);
	}
	else if (!oserr)
		socket->is_handshaking = false;
	
}

/**
 *
 *
 */
void
emailz_socket_handle_write (emailz_socket_t socket, char *buffer, ssize_t bufferlen, dispatch_io_handler_t handler)
{
	if (!socket)
		return;
	
	if (!buffer)
		return;
	
	if (bufferlen == -1)
		bufferlen = strlen(buffer);
	
	if (socket->sslcontext) {
		size_t processed = 0;
		OSStatus error = SSLWrite(socket->sslcontext, buffer, bufferlen, &processed);
		
		if (errSSLWouldBlock == error)
			printf("%s.. ssl error! why is it blocking?\n", __PRETTY_FUNCTION__);
		else if (error)
			printf("%s.. ssl error! %d\n", __PRETTY_FUNCTION__, error);
	}
	else {
		if (!handler)
			handler = ^ (bool done, dispatch_data_t data, int error) {
				if (error) {
					//XLOG("[%s:%hu] failed to dispatch_io_write(), %s [%d]", socket->addrstr, socket->port, strerror(error), error);
					emailz_socket_stop(socket);
				}
			};
		
		socket->outbytes += bufferlen;
		socket->emailz->bytes_sent += bufferlen;
		
		//XLOG("[%s:%hu] sending %lu bytes", socket->addrstr, socket->port, bufferlen);
		
		dispatch_data_t data = dispatch_data_create(buffer, bufferlen, socket->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
		dispatch_io_write(socket->channel, 0, data, socket->queue, handler);
		dispatch_release(data);
	}
}

/**
 *
 *
 */
bool
emailz_socket_read_line (emailz_socket_t socket)
{
	if (!socket)
		return false;
	
	__block unsigned char *lineptr = socket->line;
	__block size_t linelen = 0;
	__block bool found_cr=false, found_lf=false;
	
	socket->line[0] = '\0';
	socket->linelen = 0;
	socket->lineoff = 0;
	
	dispatch_data_apply(socket->indata, ^ bool (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
		const unsigned char *buffer_ptr = buffer;
		const unsigned char *buffer_end = buffer + size;
		
		while (buffer_ptr < buffer_end) {
			if (!found_cr && *buffer_ptr == '\r')
				found_cr = true;
			else if (found_cr && *buffer_ptr == '\n')
				found_lf = true;
			else if (found_cr && *buffer_ptr != '\n')
				found_cr = false;
			
			*lineptr = *buffer_ptr;
			lineptr += 1;
			linelen += 1;
			buffer_ptr += 1;
			
			if (found_cr && found_lf)
				return false;
			else if (EMAILZ_MAX_LINE_SIZE <= linelen)
				return false;
		}
		
		return true;
	});
	
	if ((found_cr && found_lf) || EMAILZ_MAX_LINE_SIZE == linelen) {
		dispatch_data_t indata = socket->indata;
		socket->indata = dispatch_data_create_subrange(indata, linelen, dispatch_data_get_size(indata)-linelen);
		dispatch_release(indata);
		
		//if (found_cr && found_lf)
		//	linelen -= 2;
		
		socket->line[linelen] = '\0';
		socket->linelen = linelen;
		
		return true;
	}
	else {
		socket->line[0] = '\0';
		return false;
	}
}

/**
 *
 *
 */
void
emailz_socket_read_command (emailz_socket_t socket)
{
	if (!socket)
		return;
	
	socket->cmnd[0] = '\0';
	socket->cmndlen = 0;
	
	if (socket->linelen == 0)
		return;
	
	unsigned char *lineptr = socket->line;
	unsigned char *cmndptr = socket->cmnd;
	unsigned char *lineend = lineptr + socket->linelen;
	size_t cmndlen = 0;
	size_t lineoff = 0;
	
	// skip leading white space
	while (*lineptr == ' ' && lineptr < lineend)
		lineptr += 1;
	
	// copy the command word
	while (lineptr < lineend && cmndlen < EMAILZ_MAX_CMND_SIZE-1) {
		char c = *lineptr;
		
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			*cmndptr = toupper(c);
			cmndptr += 1;
			cmndlen += 1;
			lineptr += 1;
		}
		else
			break;
	}
	
	// advance to the arg
	while (lineptr < lineend) {
		char c = *lineptr;
		
		if (c == ':' || c == ' ') {
			lineoff += 1;
			lineptr += 1;
		}
		else
			break;
	}
	
	socket->cmnd[cmndlen] = '\0';
	socket->lineoff = cmndlen + lineoff;
	socket->cmndlen = cmndlen;
}

/**
 *
 *
 */
void
emailz_socket_record (emailz_socket_t socket, dispatch_data_t data)
{
	if (!socket)
		return;
	
	if (!data)
		return;
	
	if (!socket->record)
		return;
	
	dispatch_data_apply(data, ^ bool (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
		if (size == fwrite(buffer, 1, size, socket->record))
			return true;
		else {
			XLOG("[%s:%hu] an error occurred while writing %lu bytes to the record file [%s]", socket->addrstr, socket->port, size, socket->record_path);
			emailz_socket_record_close(socket);
			return false;
		}
	});
}

/**
 *
 *
 */
bool
emailz_socket_record_open (emailz_socket_t socket)
{
	if (!socket)
		return false;
	
	char *name = socket->record_name;
	char *path = socket->record_path;
	char *path_ptr = path;
	
	// base
	strcpy(path_ptr, socket->emailz->record_base);
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	path_ptr += strlen(path);
	
	// yyyy
	*path_ptr = name[0]; path_ptr++;
	*path_ptr = name[1]; path_ptr++;
	*path_ptr = name[2]; path_ptr++;
	*path_ptr = name[3]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// mm
	*path_ptr = name[4]; path_ptr++;
	*path_ptr = name[5]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// dd
	*path_ptr = name[6]; path_ptr++;
	*path_ptr = name[7]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// hh
	*path_ptr = name[8]; path_ptr++;
	*path_ptr = name[9]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// mm
	*path_ptr = name[10]; path_ptr++;
	*path_ptr = name[11]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// ss
	*path_ptr = name[12]; path_ptr++;
	*path_ptr = name[13]; path_ptr++;
	*path_ptr = '/';     path_ptr++;
	mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IRWXO | S_IXOTH);
	
	// file
	strcpy(path_ptr, name);
	path_ptr += strlen(name);
	
	// .socket
	strcpy(path_ptr, ".socket");
	path_ptr += 7;
	
	if (NULL == (socket->record = fopen(path, "w"))) {
		XLOG("[%s:%hu] failed to fopen(%s), %s", socket->addrstr, socket->port, path, strerror(errno));
		return false;
	}
	
	return true;
}

/**
 *
 *
 */
void
emailz_socket_record_close (emailz_socket_t socket)
{
	if (!socket)
		return;
	
	if (!socket->record)
		return;
	
	fclose(socket->record);
	socket->record = NULL;
}





#pragma mark - socket - public

/**
 *
 *
 */
void
emailz_socket_set_smtp_handler (emailz_socket_t socket, emailz_smtp_handler_t handler, uint64_t smtp_mask)
{
	if (!socket)
		return;
	
	if (socket->smtp_handler) {
		Block_release(socket->smtp_handler);
		socket->smtp_handler = NULL;
	}
	
	if (handler) {
		socket->smtp_handler = (emailz_smtp_handler_t)Block_copy(handler);
		socket->smtp_handler_mask = smtp_mask;
	}
}

/**
 *
 *
 */
void
emailz_socket_set_auth_handler (emailz_socket_t socket, emailz_auth_handler_t handler)
{
	if (!socket)
		return;
	
	if (socket->auth_handler) {
		Block_release(socket->auth_handler);
		socket->auth_handler = NULL;
	}
	
	if (handler)
		socket->auth_handler = (emailz_auth_handler_t)Block_copy(handler);
}

/**
 *
 *
 */
void
emailz_socket_set_header_handler (emailz_socket_t socket, emailz_header_handler_t handler)
{
	if (!socket)
		return;
	
	if (socket->header_handler) {
		Block_release(socket->header_handler);
		socket->header_handler = NULL;
	}
	
	if (handler)
		socket->header_handler = (emailz_header_handler_t)Block_copy(handler);
}

/**
 *
 *
 */
void
emailz_socket_set_data_handler (emailz_socket_t socket, emailz_data_handler_t handler)
{
	if (!socket)
		return;
	
	if (socket->data_handler) {
		Block_release(socket->data_handler);
		socket->data_handler = NULL;
	}
	
	if (handler)
		socket->data_handler = (emailz_data_handler_t)Block_copy(handler);
}

/**
 *
 *
 */
char *
emailz_socket_get_name (emailz_socket_t socket)
{
	if (!socket)
		return NULL;
	else
		return socket->record_name;
}

/**
 *
 *
 */
char *
emailz_socket_get_addrstr (emailz_socket_t socket)
{
	if (!socket)
		return NULL;
	else
		return socket->addrstr;
}





#pragma mark - listener

/**
 *
 *
 */
emailz_listener_t
emailz_listener_create (emailz_t emailz, uint16_t port)
{
	emailz_listener_t listener = malloc(sizeof(struct emailz_listener_s));
	memset(listener, 0, sizeof(struct emailz_listener_s));
	
	listener->queue = emailz->listener_queue;
	listener->port = port;
	
	return listener;
}

/**
 *
 *
 */
bool
emailz_listener_start (emailz_listener_t listener)
{
	if (!listener)
		return false;
	
	int sock, reuse=1, nodelay=1;
	struct sockaddr_in soaddr;
	
	// create the socket
	if (-1 == (sock = socket(AF_INET, SOCK_STREAM, 0))) {
		printf("%s.. failed to socket(), %s\n", __PRETTY_FUNCTION__, strerror(errno));
		return false;
	}
	
	// make the socket reuseable
	if (0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
		printf("%s.. failed to setsockopt(SO_REUSEADDR), %s\n", __PRETTY_FUNCTION__, strerror(errno));
		goto fail;
	}
	
	// do not queue up outgoing data on the socket
	if (0 != setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay))) {
		printf("%s.. failed to setsockopt(TCP_NODELAY=%d), %s\n", __PRETTY_FUNCTION__, nodelay, strerror(errno));
		goto fail;
	}
	
	memset(&soaddr, 0, sizeof(soaddr));
	soaddr.sin_family = AF_INET;
	soaddr.sin_port = htons(listener->port);
	soaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	// bind to the local port
	if (-1 == bind(sock, (struct sockaddr *)&soaddr, sizeof(soaddr))) {
		printf("%s.. failed to bind(), %s\n", __PRETTY_FUNCTION__, strerror(errno));
		goto fail;
	}
	
	// listen
	if (-1 == listen(sock, 100)) {
		printf("%s.. failed to listen(), %s\n", __PRETTY_FUNCTION__, strerror(errno));
		goto fail;
	}
	
	listener->socketfd = sock;
	listener->addr = soaddr;
	listener->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, listener->socketfd, 0, listener->queue);
	dispatch_source_set_event_handler(listener->source, ^{
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int sock = accept(listener->socketfd, (struct sockaddr *)&addr, &addrlen);
		
		if (sock && listener->accept_handler)
			listener->accept_handler(listener, sock, addr);
	});
	dispatch_resume(listener->source);
	
	XLOG("listener started on port %hu", listener->port);
	
	return true;
	
fail:
	close(sock);
	return false;
}

/**
 *
 *
 */
bool
emailz_listener_stop (emailz_listener_t listener)
{
	
	// TODO: implement me
	
	return false;
}

/**
 *
 *
 */
void
emailz_listener_set_accept_handler (emailz_listener_t listener, emailz_accept_handler_t handler)
{
	if (!listener)
		return;
	
	if (listener->accept_handler) {
		Block_release(listener->accept_handler);
		listener->accept_handler = NULL;
	}
	
	if (handler)
		listener->accept_handler = (emailz_accept_handler_t)Block_copy(handler);
}





#pragma mark - secure transport

/**
 * This is the SSLWrite() callback that SSLContext uses to send data to the socket. As is the case
 * with dispatch channels, this call does not block and the write does not occur until some
 * undefined point in the future. We do not block.
 */
OSStatus
emailz_sslsocket_write (SSLConnectionRef connection, const void *buffer, size_t *bufferlen)
{
	emailz_socket_t socket = (emailz_socket_t)connection;
	
	if (!socket->channel) {
		XLOG("[%s:%hu] channel is closed; stop it.", socket->addrstr, socket->port);
		return errSSLClosedAbort;
	}
	
	dispatch_data_t data = dispatch_data_create(buffer, *bufferlen, socket->queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
	dispatch_io_write(socket->channel, 0, data, socket->queue, ^(bool done, dispatch_data_t data, int error){
		if (error) {
			//XLOG("[%s:%hu] failed to dispatch_io_write(), %s [%d]", socket->addrstr, socket->port, strerror(error), error);
			emailz_socket_stop(socket);
		}
	});
	dispatch_release(data);
	
	return 0;
}

/**
 * This is the SSLRead() callback that SSLContext uses to get data from the socket. Since we run an
 * asynchronous shop around here, we only signal SSLContext to read when we've just finished
 * reading from the socket and stored data in socket->tmpdata. We do not block.
 *
 * Read as much data as we can (up to the limit of what's requested) and then shorten our tmpdata
 * buffer by that amount and return.
 *
 * If we don't have any data to offer, return errSSLWouldBlock.
 *
 */
OSStatus
emailz_sslsocket_read (SSLConnectionRef connection, void *data, size_t *datalen)
{
	emailz_socket_t socket = (emailz_socket_t)connection;
	dispatch_data_t tmpdata = socket->tmpdata;
	__block size_t remaining = *datalen;
	__block void *dataptr = data;
	size_t requested = *datalen;
	size_t available = dispatch_data_get_size(tmpdata);
	OSStatus result = noErr;
	
	// short cut if we don't have any data. we assume that the caller will never request zero bytes.
	if (0 == available) {
		*datalen = 0;
		return errSSLWouldBlock;
	}
	else if (requested > available) {
		*datalen = available;
		result = errSSLWouldBlock;
	}
	
	dispatch_data_apply(tmpdata, ^ bool (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
		memcpy(dataptr, buffer, (size = MIN(remaining, size)));
		dataptr += size;
		remaining -= size;
		return remaining;
	});
	
	size_t returning = requested - remaining;
	
	//XLOG("[%s:%hu] available=%lu, requested=%lu, returned=%lu, remaining=%lu", socket->addrstr, socket->port, available, requested, returning, (available-returning));
	
	socket->tmpdata = dispatch_data_create_subrange(tmpdata, returning, available-returning);
	dispatch_release(tmpdata);
	
	return result;
}





#pragma mark - misc

/**
 *
 *
 */
char *
emailz_print_number (char *_dst, uint64_t num, int pad)
{
	if (!_dst)
		return NULL;
	
	int digits = (int)floor(1. + log10((double)num));
	char *dst = _dst;
	uint64_t tmp;
	
	// zero padding
	if (digits < pad) {
		switch (pad) {
			case 6:
				*(dst+5) = '0';
			case 5:
				*(dst+4) = '0';
			case 4:
				*(dst+3) = '0';
			case 3:
				*(dst+2) = '0';
			case 2:
				*(dst+1) = '0';
			case 1:
				*(dst+0) = '0';
		}
		
		dst += pad - digits;
	}
	
	// digits
	switch (digits) {
		case 6:
			tmp = num / 100000;
			*(dst+digits-6) = (char)(0x30 + tmp);
			num -= tmp * 100000;
		case 5:
			tmp = num / 10000;
			*(dst+digits-5) = (char)(0x30 + tmp);
			num -= tmp * 10000;
		case 4:
			tmp = num / 1000;
			*(dst+digits-4) = (char)(0x30 + tmp);
			num -= tmp * 1000;
		case 3:
			tmp = num / 100;
			*(dst+digits-3) = (char)(0x30 + tmp);
			num -= tmp * 100;
		case 2:
			tmp = num / 10;
			*(dst+digits-2) = (char)(0x30 + tmp);
			num -= tmp * 10;
		case 1:
			*(dst+digits-1) = (char)(0x30 + num);
	}
	
	return _dst + MAX(pad,digits);
}

/**
 *
 *
 */
uint64_t
emailz_current_time_millis ()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;
}

/**
 * Given an address and its address family, places the string form of that address into the 
 * provided pointer. Make sure there's plenty of space for the string.
 */
void
emailz_addrstr (void *addr, int family, char *addrstr)
{
	if (!addr)
		return;
	
	if (!addrstr)
		return;
	
	char buf[INET6_ADDRSTRLEN] = { 0 };
	const char *bufptr;
	
	bufptr = inet_ntop(family, addr, buf, sizeof(buf));
	
	if (NULL == bufptr) {
		XLOG("failed to inet_ntop(), %s", strerror(errno));
	}
	else {
		size_t buflen = strlen(bufptr);
		memcpy(addrstr, bufptr, buflen);
		addrstr[buflen] = '\0';
	}
}

/**
 *
 *
 */
static void
hexdump (uint8_t *buf, int len)
{
  int i, j, k;
  
  printf("     -------------------------------------------------------------------------------\n");
  
  for (i = 0; i < len;) {
    printf("     ");
    
    for (j = i; j < i + 8 && j < len; j++)
      printf("%02x ", (unsigned char)buf[j]);
		
    // if at this point we have reached the end of the packet data, we need to
    // pad this last line such that it becomes even with the rest of the lines.
    if (j >= len - 1) {
      for (k = len % 16; k < 8; k++)
        printf("   ");
    }
    
    printf("  ");
    
    for (j = i + 8; j < i + 16 && j < len; j++)
      printf("%02x ", (unsigned char)buf[j]);
		
    // if at this point we have reached the end of the packet data, we need to
    // pad this last line such that it becomes even with the rest of the lines.
    if (j >= len - 1) {
      for (k = 16; k > 8 && k > len % 16; k--)
        printf("   ");
    }
    
    printf("  |  ");
    
    for (j = i; j < i + 16 && j < len; j++) {
      if ((int)buf[j] >= 32 && (int)buf[j] <= 126)
        printf("%c", (unsigned char)buf[j]);
      else
        printf(".");
    }
		
    printf("\n");
    i += 16;
  }
  
  printf("     -------------------------------------------------------------------------------\n");
}

//  Created by Matt Gallagher on 2009/06/03.
//  Copyright 2009 Matt Gallagher. All rights reserved.
//
//  This software is provided 'as-is', without any express or implied
//  warranty. In no event will the authors be held liable for any damages
//  arising from the use of this software. Permission is granted to anyone to
//  use this software for any purpose, including commercial applications, and to
//  alter it and redistribute it freely, subject to the following restrictions:
//
//  1. The origin of this software must not be misrepresented; you must not
//     claim that you wrote the original software. If you use this software
//     in a product, an acknowledgment in the product documentation would be
//     appreciated but is not required.
//  2. Altered source versions must be plainly marked as such, and must not be
//     misrepresented as being the original software.
//  3. This notice may not be removed or altered from any source
//     distribution.
//
//  ------------------------------------------------------------------------------------------------
//
//  Altered from the original to remove calls to malloc().
//

#define xx 65
#define BINARY_UNIT_SIZE 3
#define BASE64_UNIT_SIZE 4
static unsigned char base64EncodeLookup[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char base64DecodeLookup[256] =
{
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, 62, xx, xx, xx, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, xx, xx, xx, xx, xx, xx,
	xx,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, xx, xx, xx, xx, xx,
	xx, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
};

/**
 *
 *
 */
static void *
NewBase64Decode (const char *inputBuffer, size_t length, char *outputBuffer, size_t *outputLength)
{
	if (length == -1)
		length = strlen(inputBuffer);
	
	size_t i=0, j=0; //, outputBufferSize = ((length+BASE64_UNIT_SIZE-1) / BASE64_UNIT_SIZE) * BINARY_UNIT_SIZE;
//unsigned char *outputBuffer = (unsigned char *)malloc(outputBufferSize);
	
	while (i < length) {
		unsigned char accumulated[BASE64_UNIT_SIZE];
		size_t accumulateIndex = 0;
		while (i < length)
		{
			unsigned char decode = base64DecodeLookup[inputBuffer[i++]];
			if (decode != xx)
			{
				accumulated[accumulateIndex] = decode;
				accumulateIndex++;
				
				if (accumulateIndex == BASE64_UNIT_SIZE)
					break;
			}
		}
		
		if(accumulateIndex >= 2)
			outputBuffer[j] = (accumulated[0] << 2) | (accumulated[1] >> 4);
		if(accumulateIndex >= 3)
			outputBuffer[j + 1] = (accumulated[1] << 4) | (accumulated[2] >> 2);
		if(accumulateIndex >= 4)
			outputBuffer[j + 2] = (accumulated[2] << 6) | accumulated[3];
		j += accumulateIndex - 1;
	}
	
	if (outputLength)
		*outputLength = j;
	
	return outputBuffer;
}

/**
 *
 *
 */
static char *
NewBase64Encode (const void *buffer, size_t length, bool separateLines, size_t *outputLength)
{
	const unsigned char *inputBuffer = (const unsigned char *)buffer;
	
#define MAX_NUM_PADDING_CHARS 2
#define OUTPUT_LINE_LENGTH 64
#define INPUT_LINE_LENGTH ((OUTPUT_LINE_LENGTH / BASE64_UNIT_SIZE) * BINARY_UNIT_SIZE)
#define CR_LF_SIZE 2
	
	size_t outputBufferSize = ((length / BINARY_UNIT_SIZE) 	+ ((length % BINARY_UNIT_SIZE) ? 1 : 0)) * BASE64_UNIT_SIZE;
	
	if (separateLines)
		outputBufferSize += (outputBufferSize / OUTPUT_LINE_LENGTH) * CR_LF_SIZE;
	
	outputBufferSize += 1;
	
	char *outputBuffer = (char *)malloc(outputBufferSize);
	
	if (!outputBuffer)
		return NULL;
	
	size_t i = 0;
	size_t j = 0;
	const size_t lineLength = separateLines ? INPUT_LINE_LENGTH : length;
	size_t lineEnd = lineLength;
	
	while (true)
	{
		if (lineEnd > length)
			lineEnd = length;
		
		for (; i + BINARY_UNIT_SIZE - 1 < lineEnd; i += BINARY_UNIT_SIZE)
		{
			outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
			outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4) | ((inputBuffer[i + 1] & 0xF0) >> 4)];
			outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i + 1] & 0x0F) << 2) | ((inputBuffer[i + 2] & 0xC0) >> 6)];
			outputBuffer[j++] = base64EncodeLookup[inputBuffer[i + 2] & 0x3F];
		}
		
		if (lineEnd == length)
			break;
		
		outputBuffer[j++] = '\r';
		outputBuffer[j++] = '\n';
		lineEnd += lineLength;
	}
	
	if (i + 1 < length)
	{
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
		outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4) | ((inputBuffer[i + 1] & 0xF0) >> 4)];
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i + 1] & 0x0F) << 2];
		outputBuffer[j++] =	'=';
	}
	else if (i < length)
	{
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
		outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0x03) << 4];
		outputBuffer[j++] = '=';
		outputBuffer[j++] = '=';
	}
	
	outputBuffer[j] = 0;
	
	if (outputLength)
		*outputLength = j;
	
	return outputBuffer;
}
