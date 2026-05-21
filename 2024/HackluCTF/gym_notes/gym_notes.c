#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_NOTE_SIZE 1000

struct Note {
  char data[MAX_NOTE_SIZE];
};

struct Note *notes;
static short lastNoteIndex = 0;

void showNote() {
  printf("Choose a note u want to inspect \n", lastNoteIndex);
  printf("> \n");

  short option;
  scanf("%hd", &option);
  getchar();


  option++;
  if(option < 0 || option > lastNoteIndex) {
    printf("Note not found..\n");
    return;
  }

  printf("Note consists of: %s\n\n", notes[option].data);
}

void addNote() {
  char *line = NULL;
  size_t len = 0;
  short nread; 

  if(lastNoteIndex > MAX_NOTE_SIZE) {
    printf("Max notes reached..");
    return;
  }

  printf("Write a note (max. %d characters)\n", MAX_NOTE_SIZE); 
  printf("> \n");
  nread = getline(&line, &len, stdin);

  if(nread >= MAX_NOTE_SIZE) {
    printf("Too many characters, adding note failed..\n");
    return;
  }

  lastNoteIndex++;
  notes = realloc(notes, (lastNoteIndex+1)*sizeof(struct Note));
  strcpy(notes[lastNoteIndex].data, line);
  printf("Note added!\n");
}

void editNote() {
  printf("Choose a note u want to edit\n");
  printf("> \n");

  short option;
  scanf("%hd", &option);
  getchar();

  option++; 
  if(option < 0 || option > lastNoteIndex) {
    printf("Note not found..\n");
    return;
  }

  printf("What would u like to replace it with?\n");

  char *line = NULL;
  size_t len = 0;
  short nread; 

  printf("Write a note (max. %d characters)\n", MAX_NOTE_SIZE);
  printf("> \n");
  nread = getline(&line, &len, stdin);

  if(nread >= MAX_NOTE_SIZE) {
    printf("Too many characters, adding note failed..\n");
    return;
  }

  strcpy(notes[option].data, line);
  printf("Note edited!\n");
}

void delNote() {
  printf("Function 0x%lx isn't implemented yet..\n", (void*)delNote);
}

void (**optionFuncs)();
int optionFuncsSize;
  void allowFunctionsExec(int callFromMain, int mode) {
    if(mode % 2 == 0) {
      if (mprotect(optionFuncs, optionFuncsSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        exit(1);
      } 
      else {
        printf("mprotect at 0x%lx..\n", optionFuncs);
        return;
      }

      if(mode % 2 != 0 || !callFromMain)
        exit(1);
    }
  }

int main(int argc, char *argv[]) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  notes = malloc(sizeof(struct Note));
  strcpy(notes[0].data, "Example Note\n");

 optionFuncsSize = sysconf(_SC_PAGESIZE); //_SC_PAGESIZE = 30 => optionFuncsSize = 0x1000
  if (posix_memalign((void**)&optionFuncs, optionFuncsSize, optionFuncsSize) != 0) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(1); 
  }
  //optionFuncs = 0x555555a000
  optionFuncs[0] = showNote;
  optionFuncs[1] = addNote;
  optionFuncs[2] = delNote;
  optionFuncs[3] = editNote;

  allowFunctionsExec(1, 1);

  printf("Welcome to GymNotes!\n");
  short option;
  while(1) {
    printf("1. Show Note\n");
    printf("2. Add Note\n");
    printf("3. Delete Note\n");
    printf("4. Edit Note\n");
    printf("> \n");
    //fflush(stdout);

    scanf("%hd", &option);
    getchar();
    if (option >= 1 && option <= 4) {
      (*optionFuncs[option - 1])();
    } else {
      printf("Invalid option\n");
    }
  }

  return 0;
}

