#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

_Bool check_printable(int a){
	return a > 31 && a <= 126;
}

int cpystring(char *src){
	char dest[28];
	strcpy(dest, src);
	return 0;
}

int main(){
	size_t v1;
	struct stat stat_buf;
	char s[2400];
	size_t len;
	int fd;
	unsigned int i;

	write(1, "You maybe feel some familiar with this challenge ? \n", 0x34u);
	sleep(1u);
	write(1, "Yes, I made a little change \n", 0x1Du);
	sleep(1u);
	write(1, "GO : ) \n", 8u);
	scanf("%2400s", s);
	fd = open("./libc.so", 0);
	if(fstat(fd, &stat_buf) < 0)
		return puts("open error . contact admin");
	len = stat_buf.st_size;
	if(mmap((void *)0x5555E000, stat_buf.st_size, 5, 2, fd, 0) != (void *)0x5555E000)
		return puts("mmap error! contact admin");
	for(i=0; ; ++i){
		v1 = strlen(s);
    	if ( v1 <= i )
      		break;
    	if ( !check_printable(s[i]) ){
			write(1, "Well, You haven't read the checker ???\n", 0x27u);
			exit(0);
		}
	}
	return cpystring(s);
}
