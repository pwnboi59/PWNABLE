#include <obstack.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

typedef unsigned char u8;

enum error { OK, IN_USE, NO_KELLER, KELLER_FULL, FUNNY, KELLER_EMPTY };
typedef enum error error;

int eputs(char *s) { return printf("Error: %s\n", s); };

void handle_error(error err) {
  switch (err) {
  case OK:
    break;
  case IN_USE:
    eputs("keller is in use.");
    break;
  case NO_KELLER:
    eputs("there is no keller here?");
    break;
  case KELLER_EMPTY:
    eputs("there is nothing in ze keller?");
    break;
  case KELLER_FULL:
    eputs("the keller is full.");
    break;
  case FUNNY:
    eputs("funny abuser");
    break;
  }
}

#define HANDLE(x)                                                              \
  if ((x) != OK)                                                               \
    handle_error(x);

struct keller {
  struct obstack *obs;
  u8 **elements;
  size_t size;
  size_t curr;
};

typedef struct keller keller_t;

error kellerbau(keller_t **ret, size_t size) {
  if (*ret != NULL) {
    return IN_USE;
  }
  keller_t *k = calloc(1, sizeof(keller_t));
  k->obs = calloc(1, sizeof(struct obstack));
  obstack_init(k->obs);
  k->elements = obstack_alloc(k->obs, sizeof(u8 *) * size);
  k->size = size;
  k->curr = 0;
  *ret = k;
  return OK;
}

error kellerabriss(keller_t **ret) {
  if (*ret == NULL) {
    return NO_KELLER;
  }

  keller_t *k = *ret;
  obstack_free(k->obs, NULL);
  free(k->obs);
  free(k);
  *ret = NULL;
  return OK;
}

error einkellern(keller_t *k) {
  if (k == NULL) {
    return NO_KELLER;
  }
  if (k->curr == k->size) {
    return KELLER_FULL;
  }

  char element;
  obstack_blank(k->obs, 0);
  getchar(); // eat up trailing newline
  printf("data: ");
  int i = 0;
  while ((element = getchar()) != '\n' && i++ <= 0x200) {
    obstack_1grow(k->obs, element);
  }
  obstack_1grow(k->obs, 0);
  k->elements[k->curr++] = obstack_finish(k->obs);
  return OK;
};

error auskellern(keller_t *k) {
  if (k == NULL) {
    return NO_KELLER;
  };
  if (k->curr == 0) {
    return KELLER_EMPTY;
  }
  k->curr--;
  printf("el: %s\n", (char *)k->elements[k->curr]);
  return OK;
}

keller_t *hauptkeller = NULL;
keller_t *nebenkeller = NULL;

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("Willkommen beim Kellerspeicher System! Bauen sie ihren ersten keller "
         "und lagern dort all ihre wichtigen Gegenstände.\n\n"
         "Wählen sie eine der folgenden Aktionen:\n"
         "1.  Bau eines neuen Hauptkellers\n"
         "2.  Bau eines neuen Nebenkellers\n"
         "3.  Den Hauptkeller abreisen\n"
         "4.  Den Nebenkeller abreisen\n"
         "5.  Ein Element in den Hauptkeller einkellern\n"
         "6.  Ein Element in den Nebenkeller einkellern\n"
         "7.  Ein Element aus dem Hauptkeller auskellern\n"
         "8.  Ein Element aus dem Nebenkeller auskellern\n"
         "9.  Das System herunterfahren\n");
  uint32_t auswahl;

  while (1) {
    printf("Ihre Wahl: ");
    if (scanf("%u", &auswahl) != 1) {
      exit(-1);
    }
    switch (auswahl) {
    case 1:
      printf("Größe des Kellers: ");
      if (scanf("%u", &auswahl) != 1) {
        exit(-1);
      }
      HANDLE(kellerbau(&hauptkeller, auswahl)); // kellerbau(return, size)
      break;
    case 2:
      printf("Größe des Kellers: ");
      if (scanf("%u", &auswahl) != 1) {
        exit(-1);
      }
      HANDLE(kellerbau(&nebenkeller, auswahl));
      break;
    case 3:
      HANDLE(kellerabriss(&hauptkeller));
      break;
    case 4:
      HANDLE(kellerabriss(&nebenkeller));
      break;
    case 5:
      HANDLE(einkellern(hauptkeller));
      break;
    case 6:
      HANDLE(einkellern(nebenkeller));
      break;
    case 7:
      HANDLE(auskellern(hauptkeller));
      break;
    case 8:
      HANDLE(auskellern(nebenkeller));
      break;
    case 9:
      exit(0);
      break;
    default:
      HANDLE(FUNNY);
    }
  }
};
