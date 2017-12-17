#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <map>

#define bufsize 2000000

char reply[]="HTTP/1.1 200 Connection estabilshed\r\n\r\n";
char buf[bufsize];

void error(char *msg){
	perror(msg);
	exit(1);
}

void init_openssl(){
	system("cd cert && ./_init_site.sh");
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl(){
		EVP_cleanup();
}

SSL_CTX *create_context(){
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx=SSL_CTX_new(method);
	if(!ctx){
		perror("Unable to create SSL_contet\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

SSL_CTX *load_client_context(){
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_client_method();

  ctx=SSL_CTX_new(method);
  if(!ctx){
    perror("Unable to create SSL_contet\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

SSL_CTX* generate_context(char* s){
	char buffer[1000];
	char pem[300];
	char key[300];

	SSL_CTX *ctx=create_context();

	SSL_CTX_set_ecdh_auto(ctx,1);

	sprintf(pem,"certs/%s.pem",s);
	sprintf(key,"certs/%s.key",s);

	if(access(pem,0)<0){
		sprintf(buffer,"cd cert && ./_make_site.sh %s && cp %s.pem ../certs/ && cp %s.key ../certs/%s.key",s,s,s,s);
		system(buffer);
	}

	if(SSL_CTX_use_certificate_file(ctx,pem,SSL_FILETYPE_PEM)<=0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if(SSL_CTX_use_PrivateKey_file(ctx,key,SSL_FILETYPE_PEM)<=0){
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	printf("good\n");
	return ctx;
}

std::map<std::string,SSL_CTX*> keymap;

SSL_CTX* load_server_context(char* s){
	std::string str=s;

	if(keymap.count(str)){
		SSL_CTX *tr = keymap[str];

		while(tr==NULL){
			sleep(1);
			tr=keymap[str];
		}
		return tr;
	}

	keymap[str]=NULL;
	return (keymap[str]=generate_context(s));
}

int setclient(char* hostname,int port){
  int client_fd;
  struct sockaddr_in serveraddr;
  struct hostent *server;

  client_fd=socket(AF_INET,SOCK_STREAM,0);
  if(client_fd<0)error("ERROR opening socket\n");

  server=gethostbyname(hostname);
  if(server==NULL){
    fprintf(stderr,"ERROR, no such host as %s\n",hostname);
    exit(0);
  }

  serveraddr.sin_family=AF_INET;
  bcopy((char*)server->h_addr,(char*)&serveraddr.sin_addr.s_addr,server->h_length);
  serveraddr.sin_port=htons(port);

  if(connect(client_fd,(struct sockaddr*)&serveraddr,sizeof(serveraddr))<0)error("ERROR connecting\n");

  return client_fd;
}

void* ssl_proxy(void* fd){
	int client_fd=*((int*)fd);
	int n;

	bzero(buf,bufsize);
	n=read(client_fd,buf,bufsize);
	if(n<0)error("Error reading from socket\n");
	
	if(memcmp(buf,"CONNECT",7)!=0){close(client_fd);return NULL;}

	char host[2000]={'\0',};
	for(int i=0;;i++){
		host[i]=buf[8+i];
		if(buf[8+i+1]==':'){host[i+1]='\0';break;}
	}

	printf("host:%s\n",host);

	n=write(client_fd,reply,strlen(reply));

	SSL_CTX *cctx=load_server_context(host);
	SSL *cssl=SSL_new(cctx);
	SSL_set_fd(cssl,client_fd);

	int conn=setclient(host,443);
	SSL_CTX *sctx=load_client_context();
	SSL *sssl=SSL_new(sctx);
	SSL_set_fd(sssl,conn);

	if(SSL_accept(cssl)<=0)ERR_print_errors_fp(stderr);
	if(SSL_connect(sssl)<=0){printf("dd\n");ERR_print_errors_fp(stderr);}

	int read,write;
	
	bzero(buf,bufsize);
	read=SSL_read(cssl,buf,bufsize);
	SSL_write(sssl,buf,read);

	while(1){
		bzero(buf,bufsize);
		read=SSL_read(sssl,buf,bufsize);
		if(read==0)break;
		SSL_write(cssl,buf,read);
	}

	close(client_fd);
	close(conn);
	SSL_free(cssl);
	SSL_free(sssl);
}

int setserver(int port){
	int optval=1;
	int server_fd;
	server_fd=socket(AF_INET, SOCK_STREAM,0);
	if(server_fd<0)error("ERROR opening socket\n");

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int));
	struct sockaddr_in serveraddr;
	bzero((char*)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);
	serveraddr.sin_port=htons((unsigned short)port);

	if(bind(server_fd,(struct sockaddr*)&serveraddr,sizeof(serveraddr))<0)error("ERROR on binding\n");
	if(listen(server_fd,100)<0)error("ERROR on listen\n");
	return server_fd;
}

int main(int argc, char **argv){
	init_openssl();

	int proxy_fd;
	int portno;

	if(argc!=2){
		fprintf(stderr, "usage: %s <port>\n",argv[0]);
		exit(1);
	}
	portno = atoi(argv[1]);

	proxy_fd=setserver(portno);

	struct sockaddr_in clientaddr;	
	uint clientlen=sizeof(clientaddr);
	int client_fd;

	while(1){
		client_fd=accept(proxy_fd,(struct sockaddr*)&clientaddr,&clientlen);
		if(client_fd<0)error("ERROR on accpet");

		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);	

		pthread_t thread;
		int thread_id=pthread_create(&thread,&attr,ssl_proxy,&client_fd);
		if(thread_id){
				fprintf(stderr,"pthread_create error\n");
				continue;
		}
	}
	cleanup_openssl();
	close(proxy_fd);
	return 0;
}
