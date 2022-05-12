#include <stdio.h>
#include <stdlib.h>

void main(){
	for(int i = 0; i < 90; ++i){
		char string[5];
		for(int j = 0; j < 4; ++j){
			string[j] = rand() % 26 + 97;
		}
		printf("%s\n", string);
	}	
	return;
}
