#include "json-server.h"
#include <stdio.h>

struct to_remove in_use;

/*Clean up data structures or FDs in use*/
void cleanup(void)
{
  int i;
  
  /*Clean up socket file descriptor*/
  if( in_use.sock_fd )
    close(in_use.sock_fd);

  /*Clean up prefix for IPv4 address*/
  if( in_use.prefix )
    free(in_use.prefix);

  /*Clean up socket internet address*/
  if( in_use.sock_addr )
    free(in_use.sock_addr);

  /*Clean up client structs*/
  if( in_use.clients )
  {
    for(i = 0; i < in_use.num_open; i++)
    {
      close(in_use.clients[i]->cxn_fd);
      free(in_use.clients[i]);
    }

    free(in_use.clients);
  }
}

/*Print usage and exit*/
void usage(void)
{
  /*Print usage*/
  fprintf(stderr, "Usage: json-server [IPv4 or IPv6 address]\n");

  /*Return with errors*/
  exit(EXIT_FAILURE);
}

/*When interrupt signal is received*/
void int_handler(int signum)
{
  /*Clean up any of our data structures*/
  cleanup();

  /*Exit*/
  exit(EXIT_SUCCESS);
}

/*Makes the socket and sets up its address, port, etc*/
void makeSocket(int argc, char *inputIP)
{
  char *prefix;
  int sock_fd, opt, i;
  struct sockaddr_in6 *socket_addr6;
  struct sockaddr *sock_addr;

  /*Set up the socket file descriptor*/
  if( (sock_fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1 )
  {
    perror("Error creating new socket");
    exit(EXIT_FAILURE);
  }

  /*Update socket file descriptor in struct*/
  in_use.sock_fd = sock_fd;

  /*Update option to accept IPv4 connections*/
  opt = 0;
  if( setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(int))
      != 0 )
  {
    perror("Error setting socket option to accept IPv4");
    cleanup();
    exit(EXIT_FAILURE);
  }

  /*Keep reference to socket address for cleanup*/
  opt = sizeof(struct sockaddr_in6);
  socket_addr6 = (struct sockaddr_in6 *) malloc(opt);
  in_use.sock_addr = socket_addr6;

  /*Set pointer to v6 address struct*/
  sock_addr = (struct sockaddr *) socket_addr6;
  
  /*If no address was provided:
   
   *Operate server on all addresses/bind to all services on system.
   *According to IP(7), this can be done by calling listen(2) on an
   *unbound socket. Therefore, we can skip all the converting the 
   *address and binding it to random ports until we get a hit.*/
  
  /*If address was provided*/
  if(argc == 2)
  {    
    /*Attempt to convert the given address to IPv6*/
    if( inet_pton(AF_INET6, inputIP, &socket_addr6->sin6_addr) )
    {
      /*Mark the family, flowinfo, and scope id in the socket address*/
      socket_addr6->sin6_family = AF_INET6;
      socket_addr6->sin6_flowinfo = 0;
      socket_addr6->sin6_scope_id = 0;
    }

    /*Append the given IP address to the string "::ffff:" to make an IPv4 
     *address IPv6 compliant*/
    else
    {
      /*Allocate memory for new address*/
      prefix = (char *) malloc(V4_MAX_LEN + V4_PREFIX_LEN + 1);

      /*Store reference to prefix for cleanup purposes*/
      in_use.prefix = prefix;

      /*Copy prefix into the buffer*/
      strcpy(prefix, V4_PREFIX);

      /*Copy given address after the prefix*/
      strncpy(prefix + V4_PREFIX_LEN, inputIP, V4_MAX_LEN + 1);

      /*Try again with IPv6 prefix*/
      if( inet_pton(AF_INET6, prefix, &socket_addr6->sin6_addr) )
      {
      	/*Mark the family, flowinfo, and scope id in the socket address*/
      	socket_addr6->sin6_family = AF_INET6;
      	socket_addr6->sin6_flowinfo = 0;
      	socket_addr6->sin6_scope_id = 0;
      	
      	/*Set pointer to v6 address struct*/
      	sock_addr = (struct sockaddr *) socket_addr6;
      }

      /*If neither work, complain*/
      else
      {
      	cleanup();
      	usage();
      }
    }
    
    /*Attempt to bind a name to the socket*/
    for(i = PORT_LOW; i <= PORT_HIGH; i++)
    {
      /*Try next port in list of dynamic ports*/
      socket_addr6->sin6_port = htons(i);

      /*Attempt to bind with port number*/
      if( bind(sock_fd, sock_addr, sizeof(struct sockaddr_in6)) == 0 )
      	/*Break loop because its been bound to a port successfully*/
      	break;

      perror("Unable to find open port");
      
      /*If we are at the end of usable ports and we never binded, exit*/
      if(i == PORT_HIGH)
      {
      	perror("Unable to find open port");
      	cleanup();
      	exit(EXIT_FAILURE);
      }
    }
  }

  /*Listen for new connections*/
  if( listen(sock_fd, MAX_CLIENT) != 0 )
  {
    perror("Error enabling listen on socket");
    cleanup();
    exit(EXIT_FAILURE);
  }

  /*Fill out socket address struct with current port, etc*/
  if( getsockname(sock_fd, sock_addr, (socklen_t *) &opt) != 0 )
  {
    perror("Error getting the socket name");
    cleanup();
    exit(EXIT_FAILURE);
  }

  /*If getsockname does not work*/
  if( opt != sizeof(struct sockaddr_in6) )
  {
    perror("Error getting socket name");
    cleanup();
    exit(EXIT_FAILURE);
  }

  /*If getsockname does work*/
  else
  {
    printf("HTTP server is using TCP port %d\n",
	   ntohs(socket_addr6->sin6_port));
    printf("HTTPS server is using TCP port -1\n");

    fflush(stdout);
  }
}

static long get_memory_usage_linux(void)
{
  int pid, ppid, pgrp, session, tty_nr, tpgid;
  char comm[2048], state;
  unsigned int flags;
  unsigned long minflt, cminflt, majflt, cmajflt, vsize;
  unsigned long utime, stime;
  long cutime, cstime, priority, nice, num_threads, itrealvalue, rss;
  unsigned long long starttime;

  FILE *stat = fopen("/proc/self/stat", "r");

  if(!stat)
  {
    perror("Failed to open /proc/self/stat");
    return 0;
  }

  fscanf(stat, "%d%s%c%d%d%d%d%d%u%lu%lu%lu%lu"
	 "%ld%ld%ld%ld%ld%ld%ld%ld%llu%lu%ld",
	 &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr,
	 &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
	 &utime, &stime, &cutime, &cstime, &priority, &nice,
	 &num_threads, &itrealvalue, &starttime, &vsize, &rss);

  fclose(stat);

  return vsize;
}

/*Given a client, parse what is said and put the appropriate response in 
 *the buffer*/
void parse(connection client)
{
  char *input;
  int in_len = client->buf_offset, tmp;

  /*Extract input from buffer*/
  input = (char *) malloc(sizeof(char) * in_len);
  strncpy(input, client->buf, in_len);

  /*Compare input to expected strings*/
  /*Implemented Json*/
  if( strncmp(input, get_json, in_len) == 0 )
  {
    in_use.num_req++;
    
    tmp = strlen(success_status);
    
    strncpy(client->buf, success_status, tmp);

    strncpy(client->buf + tmp, json_type, strlen(json_type));

    tmp += strlen(json_type);

    strncpy(client->buf + tmp, json_txt, strlen(json_txt));

    client->buf_offset = 0;
    client->write_end = tmp + strlen(json_txt);
  }

  /*About*/
  else if( strncmp(input, get_about, in_len) == 0 )
  {
    in_use.num_req++;
    
    tmp = strlen(success_status);
    
    strncpy(client->buf, success_status, tmp);

    strncpy(client->buf + tmp, txt_type, strlen(txt_type));

    tmp += strlen(txt_type);

    strncpy(client->buf + tmp, about_txt, strlen(about_txt));

    client->buf_offset = 0;
    client->write_end = tmp + strlen(about_txt);
  }

  /*Quit*/
  else if( strncmp(input, get_quit, in_len) == 0 )
  {
    in_use.num_req++;
    
    tmp = strlen(success_status);
    
    strncpy(client->buf, success_status, tmp);

    strncpy(client->buf + tmp, txt_type, strlen(txt_type));

    tmp += strlen(txt_type);

    strncpy(client->buf + tmp, quit_txt, strlen(quit_txt));

    client->buf_offset = 0;
    client->write_end = tmp + strlen(quit_txt);
  }

  /*Status of server*/
  else if( strncmp(input, get_status, in_len) == 0 )
  {
    char *tmp_str;
    unsigned long size;
    struct rusage usage;
    struct timeval utime, stime;

    in_use.num_req++;
    
    tmp = strlen(success_status);
    
    strncpy(client->buf, success_status, tmp);

    strncpy(client->buf + tmp, txt_type, strlen(txt_type));

    tmp += strlen(txt_type);

    /*Get usage*/
    getrusage(RUSAGE_SELF, &usage);

    /*Extract time*/
    utime = usage.ru_utime;
    stime = usage.ru_stime;

    /*Get size*/
    size = get_memory_usage_linux();

    tmp_str = malloc(sizeof(char) * 500);
    
    sprintf(tmp_str, "\r\n{"
	    "\n\t\"num_clients\": %d,\n\t\"num_requests\": %d,"
	    "\n\t\"errors\": %d,\n\t\"uptime\": %ld.%ld,"
	    "\n\t\"cpu_time\": %ld.%ld,\n\t\"memory_used\": %ld"
	    "\n}\n",
	    in_use.num_open, in_use.num_req, in_use.num_err, utime.tv_sec,
	    utime.tv_usec, stime.tv_sec, stime.tv_usec, size);

    strncpy(client->buf + tmp, tmp_str, strlen(tmp_str));

    client->buf_offset = 0;
    client->write_end = tmp + strlen(tmp_str);

    free(tmp_str);
  }

  /*If nothing matches, return 404 error*/
  else
  {
    in_use.num_err++;
    
    tmp = strlen(error_status);
    
    strncpy(client->buf, error_status, tmp);

    strncpy(client->buf + tmp, input, in_len);

    client->buf_offset = 0;
    client->write_end = tmp + in_len;
  }
}

void server(void)
{
  int i, new_fd, fd_size, write_size, max_fd;
  connection new_client, cur_client;
  fd_set read_fds, write_fds;
  
  /*Initialize the read FDs with the socket fd, zero the others*/
  max_fd = in_use.sock_fd + 1;
  FD_SET(in_use.sock_fd, &read_fds);
  FD_ZERO(&write_fds);
  
  while(1)
  {
    /*Block until we can do something*/
    select(max_fd, &read_fds, &write_fds, NULL, NULL);

    /*If there is a new connection to accept*/
    if( FD_ISSET(in_use.sock_fd, &read_fds) )
    {
      /*Accept new socket, report error if applicable*/
      if( (new_fd = accept(in_use.sock_fd, NULL, NULL)) == -1 )
      {
      	perror("Error accepting new connection");
      	cleanup();
      	exit(EXIT_FAILURE);
      }

      /*Update biggest FD if newest FD exceeds the limit*/
      if(new_fd >= max_fd)
      	max_fd = new_fd + 1;
      
      /*Allocate memory for new client*/
      new_client = (connection) malloc(sizeof(struct open_connection));

      /*Increase client list size*/
      in_use.clients = realloc(in_use.clients,
			       ++in_use.num_open * sizeof(connection));

      /*Add new connection to list of clients*/
      in_use.clients[in_use.num_open - 1] = new_client;

      /*Update client with initial info*/
      new_client->cxn_fd = new_fd;
      new_client->state = ST_READ;
      new_client->buf_offset = 0;
      new_client->place = in_use.num_open - 1;
    }

    /*Cycle through list of clients, completing what needs to be done, and
     *putting them in the right FD set, based on their current state*/
    for(i = 0; i < in_use.num_open; i++)
    {
      /*Grab pointer to current client*/
      cur_client = in_use.clients[i];

      /*Check if there is something to read*/
      if( FD_ISSET(cur_client->cxn_fd, &read_fds) )
      {
      	/*Attempt read into entire buffer*/
      	if( (fd_size = read(cur_client->cxn_fd,
      			    cur_client->buf,
      			    BUF_SIZE)) >= 0)
      	{
      	  /*Move offset by amount read*/
      	  cur_client->buf_offset += fd_size;

      	  /*Go to next state*/
      	  cur_client->state = ST_PARSE;

      	  /*Remove client from read list*/
      	  FD_CLR(cur_client->cxn_fd, &read_fds);
      	}

      	/*Read returned error value*/
      	else
      	  perror("Read error");
      }

      /*If it isn't in read fd set and its currently in read state*/
      else if(cur_client->state == ST_READ)
      	/*Add client back to read fd set*/
      	FD_SET(cur_client->cxn_fd, &read_fds);

      /*Check if there is something to write*/
      else if( FD_ISSET(cur_client->cxn_fd, &write_fds) )
      {
      	/*Determine how many bytes need to be written*/
      	write_size = cur_client->write_end - cur_client->buf_offset;

      	/*Attempt to write that many bytes*/
      	if( (fd_size = write(cur_client->cxn_fd,
      			     &(cur_client->buf[cur_client->buf_offset]),
      			     write_size)) < write_size )
      	{
      	  /*Move offset by amount written*/
      	  cur_client->buf_offset += fd_size;
      	}

      	/*If we wrote exactly what was needed*/
      	else if(fd_size == write_size)
      	{
      	  /*Move to next state*/
      	  cur_client->state = ST_CLOSE;

      	  /*Remove client from write list*/
      	  FD_CLR(cur_client->cxn_fd, &write_fds);
      	}
      }

      /*If it isn't in read fd set and its currently in read state*/
      else if(cur_client->state == ST_WRITE)
      	/*Add client back to read fd set*/
      	FD_SET(cur_client->cxn_fd, &write_fds);

      /*If client is in parse state*/
      if(cur_client->state == ST_PARSE)
      {
      	/*Parse what the client says*/
      	parse(cur_client);
      	
      	/*Change state to write*/
      	cur_client->state = ST_WRITE;

      	/*Add client to write list*/
      	FD_SET(cur_client->cxn_fd, &write_fds);
      }

      /*If client is in close state*/
      else if(cur_client->state == ST_CLOSE)
      {
      	/*Close FD*/
      	close(cur_client->cxn_fd);

      	/*Remove client from list of clients*/
      	in_use.clients[cur_client->place] = NULL;

      	/*Shift the following clients down in place and update placement*/
      	for(i = cur_client->place + 1; i < in_use.num_open; i++)
      	{
      	  (in_use.clients[i])->place--;
      	  in_use.clients[i-1] = in_use.clients[i];
      	}

      	/*Decrease client list size*/
      	in_use.clients = realloc(in_use.clients,
      				 --in_use.num_open * sizeof(connection));
      	
      	/*Free client from memory*/
      	free(cur_client);
      }
    }
    
    /*Socket fd*/
    FD_SET(in_use.sock_fd, &read_fds);
  }
}

int main(int argc, char *argv[])
{
  struct sigaction sa;
  
  /*If either not enough or too many arguments were provided*/
  if(argc != 1 && argc != 2)
    usage();

  /*Set up default values for cleanup*/
  in_use.sock_fd = 0;
  in_use.prefix = NULL;
  in_use.sock_addr = NULL;
  in_use.num_open = 0;
  in_use.num_req = 0;
  in_use.num_err = 0;
  in_use.clients = NULL;

  /*Set up interrupts*/
  sa.sa_handler = int_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  /*Have handler handle interrupt signals*/
  if( sigaction(SIGINT, &sa, NULL) == -1 )
  {
    perror("Error setting handler for sigints");
    exit(EXIT_FAILURE);
  }
  
  /*Create socket, save in structs, and output the port currently running*/
  makeSocket(argc, argv[1]);
  
  /*Call our server function, where this program will spend the rest of its 
   *life*/
  server();
  
  return 0;
}
