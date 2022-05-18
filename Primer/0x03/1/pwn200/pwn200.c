#include<stdio.h>
#include<unistd.h>

int HEYy(){
  puts("Welcome to BugsBunnyCTF!\nIts all easy you should solve it :D?");
  fflush(stdout);
  return 0;
}

ssize_t lOL()
{
  int buf[6]; // [esp+8h] [ebp-20h] BYREF

  buf[0] = 0;
  buf[1] = 0;
  buf[2] = 0;
  buf[3] = 0;
  return read(0, buf, 0x80u);
}

int main(){
	HEYy();
	lOL();
	return 0;
}