# 😎 How2heap (glibc 2.32)
> 기억해둘만한 `heap trick`들 정리

# Catalog
- [😎 How2heap (glibc 2.32)](#-how2heap-glibc-232)
- [Catalog](#catalog)
  - [Fastbin dup](#fastbin-dup)
  - [Fastbin dup consolidate](#fastbin-dup-consolidate)
  - [House of spirit](#house-of-spirit)
  - [Tcache poisoning](#tcache-poisoning)


## Fastbin dup
```c
	void *ptrs[7];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);

    free(a);
    free(b);
    free(a);
```

## Fastbin dup consolidate
```c
	void *ptr[7];

	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);

	void* p1 = calloc(1,0x40);

    free(p1);

    void* p3 = malloc(0x400); // consolidate

    free(p1);

    void* p4 = malloc(0x400);
```

## House of spirit
```c
	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}
    long fake_chunks[10] __attribute__ ((aligned (0x10)))
    
    fake_chunks[1] = 0x40;

    fake_chunks[9] = 0x1234;

    void* victim = &fake_chunks[1];
    
    free(victim);
```

## Tcache poisoning
```c
    size_t stack_ver = 0

	intptr_t *a = malloc(128);
	intptr_t *b = malloc(128);

    free(a);
    free(b);

    b[0] = (intptr_t)&stack_ver

    malloc(128);
    malloc(128);
```