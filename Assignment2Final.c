#include <math.h>
/**/
#include <stdio.h>
/*printf(),scanf(),sprintf(),sscanf(),
fprintf(),fscanf(),fgetc(),fgets(),
fclose(),fopen(),fgetpos(),
fsetpos(),rewind(),*/
#include <string.h>
/*strcpy(),memset()*/
#include <stdlib.h>
/*rand(),srand(),*/
#include <time.h>
/*time(),
Note:not including this library and running in c99(codeblocks) makes the RSA work*/


#define MAX_USERNAME_LEN 30
#define ASCII_START 0
#define ASCII_END 127
#define MAX_CAPACITY 100


struct credential{
    char username[30];
    char keytext[250];
};
typedef struct credential credential_t;

/*FUNCTION PROTOTYPES*/


/*Load And Create File*/
/*--------------------------------------------------------------------------*/
void file_menu (char * filename,int * fileloadedflag);
void load_password_list(char * filename,int * fileloadedflag);
void generate_password_list(char * filename,int * fileloadedflag);
/*--------------------------------------------------------------------------*/

/*RSA MENU*/
/*--------------------------------------------------------------------------*/
void RSA_LOAD(unsigned long long int*public_key,
              unsigned long long int*private_key);
/*--------------------------------------------------------------------------*/


/*EDIT MENU*/
/*--------------------------------------------------------------------------*/
void database_edit_menu(char * filename,unsigned long long int * public_key,
                        unsigned long long int * private_key);

void decrypt_file(char * filename ,unsigned long long int * public_key,
                  unsigned long long int * private_key);

void encrypted_input( char * filename,unsigned long long int * public_key,
                     unsigned long long int *private_key);
/*--------------------------------------------------------------------------*/





/*SAVE AND COMPRESS KEYS AND FILE*/
/*--------------------------------------------------------------------------*/
void save_working_database( unsigned long long int * public_key,
                           unsigned long long int * private_key);
void save_RSA_keys(unsigned long long int * public_key,
                  unsigned long long int * private_key);
/*--------------------------------------------------------------------------*/






/*--------------------------------------------------------------------------*/
/*RSA AND PRIME GENERATION FUNCTIONS*/
void rsa(unsigned long long int*public_key,unsigned long long int*private_key,
         unsigned long long int e);

void load_RSA_key(unsigned long long int*public_key,
                  unsigned long long int*private_key);

unsigned long long int prime_generator(void);
int primecheck(unsigned long long int n, int k);
int miillerTest(unsigned long long int d, unsigned long long int n);

unsigned long long int power(unsigned long long int x,
     unsigned long long int y, unsigned long long int p);

unsigned long long int random_numb(void);
unsigned long long int modinv(unsigned long long a, unsigned long long b);
unsigned long long int phi(unsigned long long int p, unsigned long long int q);
/*--------------------------------------------------------------------------*/
void compressAndWrite(char * filename);
/*--------------------------------------------------------------------------*/

/*COMPRESSION FUNCTIONS*/
/* Structure with information of a node */
struct huffNode {

    /* Unique input character */
    char character;

    /* Frequency of the character */
    unsigned freq;

    /* Left and right child nodes that branch from this node */
    struct huffNode *left, *right;
};

/* Structure with information about the min heap tree structure*/
struct Tree {

    /* Size of tree based on current number of nodes */
    unsigned sizenodes;

    /* Maximum number of nodes tree can have */
    unsigned maxnodes;

    /* Array of node pointers with each array element being a huffNode */
    struct huffNode** array;
};

/* Create new node with unique character character and frequency */
struct huffNode* CreateNode(char character, unsigned freq)
{
    struct huffNode* temp = (struct huffNode*) malloc(sizeof(struct huffNode));
    temp->left = temp->right = NULL;
    temp->character = character;
    temp->freq = freq;
    return temp;
}

/*Creates and allocates memory needed for binary min heap from given maxnodes*/
struct Tree* Createbinarytree(unsigned maxnodes)
{
    struct Tree* minHeap = (struct Tree*)malloc(sizeof(struct Tree));
    minHeap->sizenodes = 0;
    minHeap->maxnodes = maxnodes;
    minHeap->array =
    (struct huffNode**)malloc(minHeap->maxnodes * sizeof(struct huffNode*));
    return minHeap;
}

/*Swap position of two nodes when reogranising built huffman tree*/
void swapHuffmanNode(struct huffNode** a, struct huffNode** b)
{
    struct huffNode* i = *a;
    *a = *b;
    *b = i;
}

/* A standard implementation of MinHeapify function. */
void BinaryMinHeapify(struct Tree* minHeap, int x)
{
    int smallest = x;
    int left = 2 * x + 1;
    int right = 2 * x + 2;
    if (left < minHeap->sizenodes && minHeap->array[left]->
freq < minHeap->array[smallest]->freq)
        smallest = left;
    if (right < minHeap->sizenodes && minHeap->array[right]->
freq < minHeap->array[smallest]->freq)
        smallest = right;
    if (smallest != x) {
        swapHuffmanNode(&minHeap->array[smallest],&minHeap->array[x]);
        BinaryMinHeapify(minHeap, smallest);
        }
}

/*Checks if min heap size is 1 called to see if there is need to reorganise*/
int CheckminSize(struct Tree* minHeap)
{

    return (minHeap->sizenodes == 1);
}

/* Node is extracted from binary heap */
struct huffNode* ExtractMinNode(struct Tree* minHeap)
{

    struct huffNode* temp = minHeap->array[0];
    minHeap->array[0]
        = minHeap->array[minHeap->sizenodes - 1];

    --minHeap->sizenodes;
    BinaryMinHeapify(minHeap, 0);

    return temp;
}

/* Insert node into tree */
void InsertNode(struct Tree* minHeap,
                struct huffNode* huffNode)

{

    ++minHeap->sizenodes;
    int i = minHeap->sizenodes - 1;

    while (i && huffNode->freq < minHeap->array[(i - 1) / 2]->freq) {

        minHeap->array[i] = minHeap->array[(i - 1) / 2];
        i = (i - 1) / 2;
    }

    minHeap->array[i] = huffNode;
}

/* Builds tree with nodes, calls BinaryMinHeapify function to reorganise */
void Buildbinarytree(struct Tree* minHeap)

{

    int n = minHeap->sizenodes - 1;
    int i;

    for (i = (n - 1) / 2; i >= 0; --i)
        BinaryMinHeapify(minHeap, i);
}



/* Determines leaf node by checking if node has no children nodes  */
int isLeaf(struct huffNode* root)

{

    return !(root->left) && !(root->right);
}

/* Creates a min heap of maxnodes */
/* equal to sizenodes and inserts all character of */
/* character[] in min heap. Initially sizenodes of */
/* min heap is equal to maxnodes */
struct Tree* CreateandBuildTree(char character[], int freq[], int sizenodes)

{

    struct Tree* minHeap = Createbinarytree(sizenodes);

    int i =0;
    for( i = 0; i < sizenodes; ++i) {
        minHeap->array[i] = CreateNode(character[i], freq[i]);
    }

    minHeap->sizenodes = sizenodes;
    Buildbinarytree(minHeap);

    return minHeap;
}

/* Calls all other create and build tree functions and checks if tree needs to
be reorganised */
struct huffNode* Huffmantree(char character[], int freq[], int sizenodes)

{
    struct huffNode *left, *right, *top;


    struct Tree* minHeap = CreateandBuildTree(character, freq, sizenodes);


    while (!CheckminSize(minHeap)) {


        left = ExtractMinNode(minHeap);
        right = ExtractMinNode(minHeap);
        top = CreateNode('$', left->freq + right->freq);
        top->left = left;
        top->right = right;
        InsertNode(minHeap, top);
    }


    return ExtractMinNode(minHeap);
}


/* From the root node traversing left for 0 and right for 1 store code until
reaching a leaf node*/
void storeCode(int store[][MAX_CAPACITY],
 struct huffNode* root, int arr[], int top)
{
    int i;

    if (root->left) {
        arr[top] = 0;
        storeCode(store, root->left, arr, top + 1);
    }

    if (root->right) {
        arr[top] = 1;
        storeCode(store, root->right, arr, top + 1);
    }


    if (isLeaf(root)) {
        for ( i = 0; i <= top; i++) {
            store[root->character - ASCII_START][i] = arr[i];
        }
        store[root->character - ASCII_START][top] = -1;
    }
}
/*Writing to the file one bit at a time*/
void writeBit(int value, unsigned char *buffer, int *bufferIndex, FILE *fp)
 {
    if (value == 1) {
        int temp = 1;
        temp = temp << (7 - (*bufferIndex));
        (*buffer) = (*buffer) | temp;
    }
    (*bufferIndex)++;
    if (*bufferIndex == 8) {
        fwrite(buffer, sizeof(*buffer), 1, fp);
        *buffer = 0;
        *bufferIndex = 0;
    }
}
/*Reading from the file one bit at a time*/
int readBit(unsigned char *buffer, int *bufferIndex, FILE *fp)
{
    if (*bufferIndex == 0) {
        fread(buffer, sizeof(*buffer), 1, fp);
    }
    int temp = 1;
    temp = temp << (7 - (*bufferIndex));
    temp = (*buffer) & temp;
    temp = temp >> (7 - (*bufferIndex));

    (*bufferIndex)++;
    if (*bufferIndex == 8) {
        *buffer = 0;
        *bufferIndex = 0;
    }

    return temp;
}

/*bitshift 8 bit buffer to write encoded character to compressed file*/
void writeChar(char value, unsigned char *buffer, int *bufferIndex, FILE *fp)
{
    int i;
    for ( i = 0; i <= 7; i++) {
        int temp = 1;
        temp = temp << (7 - i);
        temp = temp & value;
        temp = temp >> (7 - i);
        writeBit(temp, buffer, bufferIndex, fp);
    }
}
/*Reads out one bit of encoded character and prefix code from compressed file */
char readChar(unsigned char *buffer, int *bufferIndex, FILE *fp)
 {
    char value = 0;
    int i;
    for (i = 0; i < 8; i++) {
        int temp = readBit(buffer, bufferIndex, fp);
        temp = temp << (7 - i);
        value = temp | value;
    }
    return value;
}
/*Write prefix code,character and original text to compressed file*/
void writeCodes(struct huffNode* root,
 unsigned char *buffer, int *bufferIndex, FILE *fp)
 {
    if (root->left && root->right) {
        writeBit(0, buffer, bufferIndex, fp);
        writeCodes(root->left, buffer, bufferIndex, fp);
        writeCodes(root->right, buffer, bufferIndex, fp);
    } else {
        writeBit(1, buffer, bufferIndex, fp);
        writeChar(root->character, buffer, bufferIndex, fp);
    }
}
/*Read prefix code,character and original text from compressed file*/
struct huffNode* readCodes(unsigned char *buffer, int *bufferIndex, FILE *fp)
 {
    struct huffNode* root = CreateNode(0, 0);
    int bit = readBit(buffer, bufferIndex, fp);

    if (bit == 0) {
        root->left = readCodes(buffer, bufferIndex, fp);
        root->right = readCodes(buffer, bufferIndex, fp);
    } else {
        root->character = readChar(buffer, bufferIndex, fp);
    }
    return root;
}
/*Main function to encode and compress text in a compressed.bin file*/
void compressAndWrite(char * filename)
{
    int i;
    char ch;

    int codes[ASCII_END - ASCII_START][MAX_CAPACITY] = {{0}};
    int allFrequency[ASCII_END - ASCII_START] = {0};
    char array[ASCII_END - ASCII_START];
    int frequency[ASCII_END - ASCII_START];
    int arrayLength = 0;

    FILE *fp;
    fp = fopen(filename,"r");


    while((ch = fgetc(fp)) && !feof(fp)) {
        if(ch>=ASCII_START && ch<=ASCII_END) {
            allFrequency[ch-ASCII_START]++;
        }
    }
    fclose(fp);

    for(i=ASCII_START; i<=ASCII_END; i++) {
        if (allFrequency[i-ASCII_START] > 0){
            array[arrayLength] = i;
            frequency[arrayLength] = allFrequency[i-ASCII_START];

            arrayLength++;
        }

    }

    struct huffNode* tree = Huffmantree(array, frequency, arrayLength);

    FILE *cp = fopen("compressed.bin","wb");
    unsigned char buffer = 0;
    int bufferIndex = 0;
    writeCodes(tree, &buffer, &bufferIndex, cp);

    int arr[MAX_CAPACITY], top = 0;
    storeCode(codes, tree, arr, top);

    fp = fopen(filename,"r");

    while((ch = fgetc(fp)) && !feof(fp)) {
        if(ch>=ASCII_START && ch<=ASCII_END) {
            int i = 0;
            while (codes[ch - ASCII_START][i] != -1 && i < MAX_CAPACITY) {
                writeBit(codes[ch - ASCII_START][i], &buffer, &bufferIndex, cp);
                i++;
            }
        }
    }

    /* Fill the current buffer to write to the file one more time */
    while (bufferIndex > 0) {
        writeBit(1, &buffer, &bufferIndex, cp);
    }
    writeChar('\n', &buffer, &bufferIndex, cp);
    fclose(fp);
    fclose(cp);
}
/*Main function to dencode and decompress bitstream from a compressed.bin file*/
void readAndDecompress()
{
    char tempfilename[20];
    tempfilename[0]='\0';
    printf("ENTER THE NAME OF THE COMPRESSED .bin FILE> ");
    scanf("%s",tempfilename);
    FILE *cp;
    cp = fopen(tempfilename,"rb");
    unsigned char buffer = 0;
    int bufferIndex = 0;

    struct huffNode* tree = readCodes(&buffer, &bufferIndex, cp);

    struct huffNode* node = tree;
    int bit = 0;
    FILE *fep = fopen("decrompressed.txt","w");
    while (bit >= 0) {
        bit = readBit(&buffer, &bufferIndex, cp);
        if (bit == 0 && node->left) {
            node = node->left;
        } else if (bit == 1 && node->right) {
            node = node->right;
        } else {
            printf("%c", node->character);
            fprintf(fep, "%c", node->character);

            if (bit == 0) {
                node = tree->left;
            } else {
                node = tree->right;
            }

        }
        if (buffer == '\n') {
            bit = -1;
        }

    }
    printf("\n");


    fclose(fep);
    fclose(cp);
}
int main(void)
{
    int menu;
    int fileloadedflag = 0;
    int keysloadedflag = 0;
    char filename[30];
    filename[0]= '\0';
    char *filenameptr;
    filenameptr = filename;
    unsigned long long int public_key =0;
    unsigned long long int private_key =0;
    /*The common variables shared across the
        program belong to main and are passed as pointers*/

    srand(time(NULL));
    /*Random number generator must be initialized in main()*/

    while (menu != 5)
    {
        printf("1. Create/Load Password File\n"
               "2. Load/Generate RSA Key for this Session\n"
               "3. Edit Database\n"
               "4. Compress & Save File\n"
               "5. Exit The Program\n");
        scanf("%d",&menu);
        if (menu == 1)
        {
            file_menu(filenameptr,&fileloadedflag);
            /*pass filename string as pointer*/
        }
        else if (menu == 2)
        {
            RSA_LOAD(&public_key,&private_key);
            if ((public_key>0 && private_key >0))
            /*if the public and private keys have
            values print them and flip the keysloadedflag*/
            {
              printf("THE PUBLIC KEY IS %llu\n",public_key);
                printf("THE PRIVATE KEY IS %llu\n",private_key);
                printf("KEYS LOADED\n");
                keysloadedflag = 1;
            }
            else
            {
                printf("KEYS DIDNT LOAD PLEASE TRY AGAIN\n");
            }
        }
        else if (menu == 3)
        {
            if ((keysloadedflag == 1))
            /* only allow editing If the keys and database file are loaded*/
            {
                if (fileloadedflag ==1)
                {
                    database_edit_menu(filenameptr,&public_key,&private_key);
                }
                else
                {
                    printf("ERROR! PLEASE LOAD FILE AND TRY AGAIN\n");
                }
            }
            else
            {
                printf("CANNOT EDIT FILE WITHOUT "
                       "RSA KEYS PLEASE LOAD AND TRY AGAIN\n");
            }
        }
        else if (menu == 4)
        {
		compressAndWrite(filenameptr);/*compresses the working file*/
        }
        else if (menu == 5)
        {
            break;/*Breaks from program*/
        }
        else if (menu>5)
        {
            printf("Invalid choice\n");/*invalid if conditions not met*/
            menu = 0;
        }
    }
    return 0;
}
/*--------------------------------------------------------------------------*/
/* MENU OPTION 1 LOAD AND CREATE FILE FUNCTIONS
This function takes the user to the file loading,creation and decompressing
operations */
void file_menu ( char * filename,int * fileloadedflag)
{
    int menu;
    while (menu !=3)
    {
        printf("1.Load Password Database File\n"
               "2.Generate New Password Database File\n"
	           "3.Load And Print Decompressed File\n"
               "4.Go Back To Main Menu\n");
        scanf("%d",&menu);
        if (menu == 1)
        {
            load_password_list(filename,fileloadedflag);
        }
        else if (menu == 2 )
        {
            generate_password_list(filename,fileloadedflag);
            /*this opens a new file*/
        }
        else if (menu == 3)
        {
            readAndDecompress();
        }
	else if (menu ==4)
	{
	    break;
	}
        else
        {
            printf("Invalid choice\n");
        }
    }
}
/*This function asks the user for the text file they wish to use*/
void load_password_list(char * filename,int * fileloadedflag)
{
    char tempfilename[10];
    tempfilename[0]='\0';
    printf("ENTER THE NAME OF THE DATABASE FILE> ");
    scanf("%s",tempfilename);
    FILE * fp;
    fp = fopen((tempfilename),("r"));
    if (fp==(NULL))
    {/*Throw Error if file doesnt exist*/
        printf("FILE DOES NOT EXIST!!!\n");

    }
    else
    {
        printf("FILE LOADED\n");
        *fileloadedflag = 1;
        strcpy(filename,tempfilename);
    }
    fclose(fp);
}
/*This function creates a new database file to be used for I/O*/
void generate_password_list(char * filename,int * fileloadedflag)
{
    char tempfilename[10];
    tempfilename[0]='\0';
    printf("ENTER THE NAME OF THE DATABASE FILE> ");
    scanf("%s",tempfilename);

    FILE *fp;

    fp = fopen(tempfilename,"a");
    if (fp==(NULL))
    {
        printf("ERROR\n");
    }
    else
    {
        *fileloadedflag = 1;
    }
    fclose(fp);
    strcpy(filename,tempfilename);
}
/*--------------------------------------------------------------------------------------------------------*/

/*MENU OPTION 2 LOAD OR GENERATE RSA MENU
This function loads previously used RSA keys from a key file
or generates new ones and overwrites the old key file*/

void RSA_LOAD(unsigned long long int*public_key,unsigned long long int*private_key)
{
    int menu;
    int e = 17;
    /*e is the prime public exponent a.k.a (fermat number)*/

    while (menu !=3)
    {
        printf("1.Load RSA KEY\n"
               "2.Generate RSA KEY\n"
               "3.Go Back To Main Menu\n");
        scanf("%d",&menu);
        if (menu == 1)
        {
            load_RSA_key(public_key,private_key);

            break;

        }
        else if (menu == 2 )
        {
            /*the inputs are passed as pointers*/
            rsa(public_key,private_key,e);
            break;
        }
        else if (menu == 3)
        {
            break;
        }
        else
        {
            printf("Invalid choice\n");/*invalid if conditions not met*/
        }
    }
}
/*--------------------------------------------------------------------------------------------------------*/

/*MENU OPTION 3 EDIT DATABASE FILE FUNCTIONS*
This functions accesses the read and write menus for the database*/
void database_edit_menu( char * filename,unsigned long long int * public_key,unsigned long long int * private_key)
{
   int menu;
   while (menu != 3)
    {
        printf("1. Display Loaded File\n"
               "2. Add Passwords to Database\n"
               "3. Exit Back to Loading Screen\n");
        scanf("%d",&menu);
        if (menu == 1)
        {
            decrypt_file(filename,public_key,private_key);
        }
        else if (menu == 2)
        {
            encrypted_input(filename,public_key,private_key);
        }
        else if (menu == 3)
        {
            break;
        }
        else
        {
            printf("Invalid choice\n");
        }
    }
}
/*This Function is used for user input of passsword credentials*/
void encrypted_input(char * filename ,unsigned long long int * public_key,unsigned long long int * private_key)
{

    int e = 17;
    char letterform[30];/*stores the inputted user password to be converted*/
    /* numberform stores the input values in their ASCII representation*/
    char numberform[30][30];
    char username[30];
    int inputask =0;/*Control for adding more entries*/
    int innerflag = 0;/*used in the while loop for that menu*/
    int input = 0;/*used to terminate this function and return to menu*/
    int i =0;
    /*stores the string in its integer form*/
    long long int password_as_numb[30];
    FILE * fp;/*file pointer*/
    printf("THE FILENAME IS: %s\n",filename);
    fp = fopen(filename,"a");
    while (input == 0)
    {

        username[0]='\0';
        password_as_numb[0]=0;
        letterform[0]='\0';
        inputask ='\0';
        for (i =0;i<30;i++)
        {
            numberform[i][0]='\0';
        }
        /*make sure the strings and values are empty*/


        printf("ENTER USERNAME:");
        scanf("%s",username);
        printf("ENTER PASSWORD:");
        scanf("%s",letterform);


        int len = strlen(letterform);


        for (i = 0; i<len;i++)/*loop through every element annd convert it*/
        {
            sprintf(numberform[i],"%d",letterform[i]);
            sscanf(numberform[i],"%lli",&password_as_numb[i]);
            /*converts the characters to their ASCII equivalent integers*/
        }


        /*encrypt the array now*/
        for (i =0;i<len;i++)
        {
            password_as_numb[i] = power(password_as_numb[i],e,*public_key);
            /*modular exponentiation function does the operation
            (x^e) % public_key very quickly  */
        }

        /*we now save our values to the database file*/
        fprintf(fp,"%s:",username);
        for (i=0;i<len;i++)
        {
            if (i != len-1)
            {
                fprintf(fp,"%lli,",password_as_numb[i]);
            }
            else
            {
                fprintf(fp,"%lli,\n",password_as_numb[i]);
            }
        }


        /*gives the option to continue adding values*/
        while (innerflag == 0)
        {
            printf("DO YOU WANT TO ADD MORE USERS Y[1]/N[2] ?>");
            scanf("%d",&inputask);
            if (inputask == 1)
            {
                innerflag = 1;
            }
            else if (inputask == 2)
            {
                input = 1;
                innerflag = 1;
                fclose(fp);
            }
            else
            {
                printf("ERROR PLEASE ENTER CORRECTLY\n");
            }
        }
        innerflag = 0;
    }

}


/*This function 1.reloads the database file
                2.decrypts the password entry back to ASCII value
                3.converts and saves those values back to their original form*/
void decrypt_file(char * filename,unsigned long long int * public_key,unsigned long long int * private_key)
{
    printf("THE FILENAME IS %s \n",filename);
    int position = 0;/*tracks the number of entries in the file*/
    int counter = 0;/*controls the iteration over the encryption*/
    int charlength=0;/*tracks the length of the username*/
    int controlposition =0;/*controls the position when editing the credential_t file*/
    long long int password_as_numb[30];
    /*same as encrypt function stores value in int*/
    int password_as_numb2[30];
    int i =0;
    char encryptedform[250];/*stores the password entry*/
    char numberform[30][40];/*stores the individual numbers for each entry*/
    char username2[30];
    char feed;/*used to move through the file*/
    char endline;
    FILE * fp;
    fp = fopen(filename,"r");
    fpos_t start;
    /*use these values to track the position in the stream*/
    fpos_t stop;
    fgetpos(fp,&start);

    while(!feof(fp))
    {
            endline = fgetc(fp);
            if(endline == '\n')
            {
                /*first we must count how many lines or entries there are*/
                position+=1;
            }
    }
    rewind(fp);

    printf("THERE ARE %d Entries\n",position);
    credential_t passwordfile[position];

    if (fp != NULL)
    {
        /*---------------*/
        username2[0]='\0';
        password_as_numb[0]=0;/*initiallize*/
        encryptedform[0]='\0';
        memset(numberform,0,sizeof(numberform));
        /*---------------*/

        while (!feof(fp) && controlposition < position)
        {
            feed = fgetc(fp);
            charlength+=1;
            if (feed == ':')
            {
                fgetpos(fp,&stop);
                fsetpos(fp,&start);
                fgets(username2,charlength,fp);
                strcpy(passwordfile[controlposition].username,username2);
                username2[0] = '\0';
                fsetpos(fp,&stop);
            }

            if (feed == ':' )
            {
                charlength = 0;
                fgetpos(fp,&start);
            }
            if (feed == '\n')
            {
                fgetpos(fp,&stop);
                fsetpos(fp,&start);
                fgets(encryptedform,charlength,fp);
                strcpy(passwordfile[controlposition].keytext,encryptedform);
                controlposition += 1;
                fsetpos(fp,&stop);
                encryptedform[0] = '\0';
            }
            if (feed == '\n')
            {
                charlength = 0;
                fgetpos(fp,&start);
            }

        }
        fclose(fp);


        /*Dividing up the keytext*/
        /*----------------------*/
        int start=0;
        int stop =0;
        int itemcount =0;
        int x =0;
        char temp[30];
        temp[0] = '\0';
        /*----------------------*/
        while (counter < position)
        {
            /*----------------------*/
            encryptedform[0]='\0';itemcount = 0;start = 0;stop = 0;
            memset(temp,0,strlen(temp));strcpy(encryptedform,passwordfile[counter].keytext);
            /*----------------------*/

            for (i =0;i<strlen(encryptedform);i++)
            {
                stop+=1;
                if (encryptedform[i]==',')
                {
                    for (x = 0;x<((stop)-start);x++)
                    {
                        if (encryptedform[(start)+x] != ',')
                        {
                                temp[x] = encryptedform[(start)+x];
                        }
                    }
                    sscanf(temp,"%lli",&password_as_numb[itemcount]);/*Reading in as integer*/
                    memset(temp,0,strlen(temp));
                    itemcount++;
                    start = stop;
                }
            }
            memset(temp,0,strlen(temp));
            for (i=0;i<itemcount;i++)
            {
                printf("%lli---------",password_as_numb[i]);
                password_as_numb[i] = power(password_as_numb[i],*private_key,*public_key);
                printf("%lli\n",password_as_numb[i]);
                password_as_numb2[i]=password_as_numb[i];/*changed here*/
                sprintf(temp,"%s%c",temp,password_as_numb2[i]);
                strcpy(numberform[counter],temp);
            }
            strcpy(passwordfile[counter].keytext,numberform[counter]);
            counter+=1;
        }
    }
    else
    {
        printf("FAILED LOADING FILE\n");
    }
    printf("USERNAME:Password\n");
    for (i=0;i<counter;i++)
    {
        printf("%s:%s\n",passwordfile[i].username,passwordfile[i].keytext);
    }
}
/*--------------------------------------------------------------------------------------------------------*/


/*MENU OPTION 4 COMPRESS AND EDIT FILE FUNCTIONS*/

void save_working_database( unsigned long long int * public_key,unsigned long long int * private_key)
{
    save_RSA_keys(public_key,private_key);
}

void save_RSA_keys(unsigned long long int * public_key,unsigned long long int * private_key)
{

}







/*BEGINING OF RSA AND PRIME GENERATION FUNCTIONS*/
/*----------------------------------------------------------------------------*/
/*This function loads RSA keys from a RSA_KEYS.txt*/
void load_RSA_key(unsigned long long int*public_key,unsigned long long int*private_key)
{
    unsigned long long int pubkey,privkey;
    FILE *fp;
    char tempchar[20];
    int i =0;
    fp = fopen("RSA_KEYS.txt","r");
    if (fp==NULL)
    {
        printf("ERROR KEY FILE NOT FOUND\n");
    }
    for (i =0; i<4;i++)
    {
        fgets(tempchar,30,fp);
        if(i == 1)
        {
             sscanf(tempchar,"%lli",&pubkey);
        }
        else if (i ==3)
        {
            sscanf(tempchar,"%lli",&privkey);
        }
    }
    fclose(fp);
    *private_key=privkey;
    *public_key=pubkey;
}
void rsa(unsigned long long int*public_key,unsigned long long int*private_key,unsigned long long int e)
{
    unsigned long long int p,q,n,phiN,d,t;
    /*p and q are the primes that make the public key
        phiN is used in the formula to generate the private key
        d and n are the private and public keys respectively
        t is used to make sure the mathematical relationship
        between the private and public keys exists*/
    int flag = 0;
    while (flag != 1)
    {
        p=0;q=0;n=0;phiN=0;d=0;t=0;
        /*Generate Primes*/
        p = prime_generator();
        q = prime_generator();

        /*Make Public Key*/
        n = p*q;

        /*calculate PHIN*/
        phiN = phi(p,q);

        /*create private key*/
        d = modinv(e,phiN);

        /*test variable to see if the variables were generated correctly*/

        t = (e*d) % phiN;
        if (t == 1)
        {
            flag = 1;
        }
    }

    *public_key = n;/*store the values*/
    *private_key = d;
    FILE * fp;
    fp = fopen("RSA_KEYS.txt","w");
    fprintf(fp,"PUBLIC_KEY:\n");/*store in txt file*/
    fprintf(fp,"%lli\n",n);
    fprintf(fp,"PRIVATE_KEY:\n");
    fprintf(fp,"%lli\n",d);
    fclose(fp);

}
/*used for the private key formula*/
unsigned long long int phi(unsigned long long int p, unsigned long long int q)
{
    unsigned long long int n;
    n = (p-1)*(q-1);
    return n;
}

/*this function is used to find the modular multiplicative inverse
it uses an implementation of the extended euclidean algorithm for faster computation*/
unsigned long long int modinv(unsigned long long int e, unsigned long long int phiN)
{
	unsigned long long int b0 = phiN, t, q;
	unsigned long long int x0 = 0;
	unsigned long long int x1 = 1;

	if (phiN == 1)
    {
        return 1;
    }

	while (e > 1) {
		q = e / phiN;
		t = phiN, phiN = e % phiN, e = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0)
    {
        x1 += b0;
    }
	return x1;
}

unsigned long long int prime_generator(void)
{
    int k = 10;  /* Number of iterations*/
    int i =0;
    unsigned long long int random_num1;
    random_num1 = random_numb();
    if (random_num1 % 2 == 0)
    {
        random_num1+=1;
    }
    for (i = 0;i<20000;i++)
    {
        if (primecheck(random_num1,k)==1)
        {
            break;

        }
        else
        {
            /*printf("Wasnt Prime\n");*/
            random_num1+=2;
        }
    }

    return random_num1;
}

int primecheck(unsigned long long int n, int k)
{
    int flag = 1;
    int i =0;
    /*trivial conditions for n*/
    if (n <= 1 || n == 4)
    {
        flag = 0;
        return flag;
    }
    if (n <= 3)
    {
        flag = 1;
        return flag;
    }

    /* Find r so that n = 2^d * r + 1 for some r >= 1*/
    unsigned long long int binaryexponent = n - 1;
    while (binaryexponent % 2 == 0)
        binaryexponent /= 2;

    /*the security value that tests a number for primality
     k times*/
    for (i = 0; i < k; i++)
         if (miillerTest(binaryexponent, n) == 0)
         {
             flag = 0;
             return flag;
         }

    return flag;
}

/*this is an implementation of the miller-rabin primality test
which an extension of fermat's little theorem for probabilistic primality testing*/
int miillerTest(unsigned long long int d, unsigned long long int n)
{
    int flag = 0;
    /*make sure that n > 4*/
    unsigned long long int a = 2 + rand() % (n - 4);
    unsigned long long int x =0;
    /* Compute a^d % n*/
    x = power(a, d, n);

    if (x == 1  || x == n-1)
    {
        flag = 1;
        return flag;
    }

    /*Keep squaring x while one of the following doesn't
      happen
     1.d does not reach n-1
     2.(x^2) % n is not 1
     3.(x^2) % n is not n-1
	*/
    while (d != n-1)
    {
        x = (x * x) % n;
        d *= 2;

        if (x == 1)
        {
            flag = 0;
            return flag;
        }
        if (x == n-1)
        {
            flag = 1;
            return flag;
        }
    }

    /*Return composite*/
    return flag;
}

/*this function is a fast way to do modular exponentiation*/
unsigned long long int power(unsigned long long int x, unsigned long long int y, unsigned long long int p)
{
    unsigned long long int res = 1;
    /*Initialize result
     Update x if it is more than or
     equal to p*/

    x = x % p;
    while (y > 0)
    {
        /* If y is odd, multiply x with result*/
        if (y & 1)
        {
            res = (res*x) % p;
        }
        /*y must be even now*/
        y = y>>1; /* y = y/2*/
        x = (x*x) % p;
    }
    return res;
}
/*this function generates a pseudo random number*/
unsigned long long int random_numb(void)
{
    unsigned long long int longnum1=0;
    char num[30];
    int i = 0;
    int x = 0;
    num[0]= '\0';
    for (x = 0 ; x < 1;x++)
    {
        for (i=0;i<1;i++)
        {
            sprintf(num,"%s%d",num,rand());
        }
    }
    sscanf(num,"%llu",&longnum1);
    return longnum1;
}


