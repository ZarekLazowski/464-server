#ifndef _JSON_SERVER_H_
#define _JSON_SERVER_H_

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>

#define V4_PREFIX "::ffff:"
#define V4_PREFIX_LEN 7
#define V4_MAX_LEN 15
#define V4_LOOP "127.0.0.1"
#define V6_LOOP "::1"

/*Lower and Upper limits of dynamic ports, respectively*/
#define PORT_LOW 49152
#define PORT_HIGH 65535

/*Program limitations*/
#define MAX_CLIENT 255
#define BUF_SIZE 65535

char *success_status = "\r\nHTTP-1.1 200 OK\r\n";
char *error_status = "\r\nHTTP-1.1 404 Not Found\r\n";

char *txt_type = "Content-Type: text/html; charset=UTF-8\r\n";
char *json_type = "Content-Type: application/json\r\n";

char *get_json = "GET /json/implemented.json\r\n";
char *json_txt = "\r\n[\n\t{\n\t\t\"feature\": \"about\"\n\t\t" 
  "\"URL\": \"/about_server\"\n\t},\n\t{\n\t\t\"feature\": \"quit\"\n\t\t"
  "\"URL\": \"/kill\"\n\t},\n\t{\n\t\t\"feature\": \"status\"\n\t\t"
  "\"URL\": \"/current_status\"\n\t}\n]\n";

char *get_about = "GET /about_server\r\n";
char *about_txt = "\r\n{\n\t\"author\": \"Zarek Lazowski\",\n\t"
  "\"email\": \"zlazowsk@calpoly.edu\",\n\t\"major\": \"CPE\"\n}\n";

char *get_quit = "GET /kill\r\n";
char *quit_txt = "\r\n{\n\t\"result\": \"success\"\n}\n";

char *get_status = "GET /current_status\r\n";

/*The different states that a client connection can be in*/
typedef enum {
	      ST_READ,
	      ST_PARSE,
	      ST_WRITE,
	      ST_CLOSE
} states;

/*Struct representing a client connection*/
typedef struct open_connection{
  int cxn_fd;
  int place;
  states state;
  char buf[BUF_SIZE];
  int buf_offset;
  int write_end;
} *connection;

/*Structure that keeps track of things that need to be removed, such as
 *file descriptors, open connections, data structures*/
typedef struct to_remove{
  int sock_fd;
  struct sockaddr_in6 *sock_addr;
  char *prefix;
  int num_open;
  int num_req;
  int num_err;
  connection *clients;
} *bundle;

/*Utilitarian functions*/
void cleanup(void);
void usage(void);

/*Programmatic functions*/
void makeSocket(int argc, char *inputIP);
static long get_memory_usage_linux(void);
void parse(connection client);
void server(void);

#endif
