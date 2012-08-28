libEmailz
=========

Fast, efficient GCD-based (partial) SMTP server. By "partial" I mean that it implements a subset of
the SMTP spec, and what it does implement it doesn't actually act on. Instead, it is up to the user
to provide callbacks for the various SMTP events and handle them appropriately. libEmailz will
transparently handle TLS/SSL connection negotation.

Your code should include the public emailz header:

	#import "emailz_public.h"

Initialize the emailz system. This will create a couple listeners on non-standard ports that any
user has access to (10025, 10587). Incoming connections on both ports are treated identically.

	emailz_t emailz = emailz_create();

libEmailz supports an optional socket logging facility. Each socket connection is logged to a 
separate file.

	emailz_record_enable(emailz, true, "/Users/someone/Desktop/EmailzLog");

Each socket connection can generate SMTP, DATA and AUTH events. There is a handler type for each of 
these event types. These handlers are set on the socket.

When registering an SMTP event handler, you can provide an optional mask of event types. If you pass
zero, you'll receive all event types. We'll show how to register this handler in a bit. Here is what
the handler itself looks like:

	emailz_smtp_handler_t smtp_handler;
	smtp_handler = ^ (emailz_t emailz, void *context, emailz_smtp_command_t, unsigned char *arg) {
		YourObject *object = (YourObject *)context;
		
		if (EMAILZ_SMTP_COMMAND_MAIL == command)
			; // ...
		else if (EMAILZ_SMTP_COMMAND_RCPT == command)
			; // ...
	};

The DATA handler is called when receiving actual email content. A final call is made to this handler
for each email with zero-length data and "done" set to true.

	emailz_data_handler_t data_handler;
	data_handler = ^ (emailz_t emailz, void *context, size_t datalen, const void *data, bool done) {
		YourObject *object = (YourObject *)context;
		
		if (!done)
			; // append the data somewhere
		else
			; // you have a complete email now
	};

Finally, the AUTH handler is called if the MTA tries to authenticate. By default, all authentication
is accepted. If you register an auth handler you can override the default behavior.

	emailz_auth_handler_t auth_handler;
	auth_handler = ^ (emailz_t emailz, void *context, char *user, char *pass) {
		YourObject *object = (YourObject *)context;
		return false;
	};

Now that we have all of our handlers defined, let's put them to use. As mentioned previously, the
SMTP, DATA and AUTH handlers are all applied in the socket context. The SOCKET handler is applied
in the emailz_t context. So, our socket handler itself will use our other handlers and register
them when a new socket is accepted.

	emailz_socket_handler_t sock_handler;
	sock_handler = ^ (emailz_t emailz, emailz_socket_t socket, emailz_socket_state_t state, void **context) {
		if (EMAILZ_SOCKET_STATE_OPEN == state) {
			YourObject *object = NewYourObject();
			*context = object;

			char *ipaddr = emailz_socket_get_addrstr(socket);
			char *socketid = emailz_socket_get_name(socket);
			
			emailz_socket_set_smtp_handler(socket, smtp_handler, EMAILZ_SMTP_COMMAND_MAIL | EMAILZ_SMTP_COMMAND_RCPT);
			emailz_socket_set_data_handler(socket, data_handler);
			emailz_socket_set_auth_handler(socket, auth_handler);
		}
		else if (EMAILZ_SOCKET_STATE_CLOSE == state) {
			YourObject *object = (YourObject *)*context;
			DeleteYourObject(object);
		}
	}

	emailz_set_socket_handler(emailz, sock_handler);

	emailz_start(emailz);
	
And the one final detail is the self-signed private key (.p12) file for TLS/SSL support, which needs
to be specified in the emailz_start() function in emailz.c. This will be fixed/improved later. A
compiler warning will show you the line of code that needs to be altered.

And that's all there is to it.

Regarding performance, all IO uses GCD's channel feature which means that everything is asynchronous.
Dozens of threads do not sit around idly waiting for sockets to send data. Memory use while under 
heavy load will likely not exceed 2MB. Using postal v0.72 the bottleneck was my test machine's 
ability to send email which topped out at 400/sec while the libEmailz machine was at about 
50-percent capacity of one cpu core. libEmailz will not be the bottleneck in your program.
