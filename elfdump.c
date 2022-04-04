#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>


void izpisi(Elf32_Phdr *t,uint32_t v,const char* ime)
{
        if (t->p_type == v) {
        printf("%-20s0x%06X 0x%08X 0x%08X 0x%06X 0x%06X ", ime,t->p_offset,t->p_vaddr,t->p_paddr,t->p_filesz,t->p_memsz);
        (t->p_flags&PF_R )?printf("R"):printf(" ");
        (t->p_flags&PF_W )?printf("W"):printf(" ");
        (t->p_flags&PF_X )?printf("E"):printf(" ");
        printf(" ");
        printf("0x%hX\n",t->p_align);


    }
}

Elf32_Ehdr parse_program_header(char *fp)
{
    Elf32_Ehdr header = *((Elf32_Ehdr*)(fp));
    


    printf("Elf header:\nMagic:   ");
    
    for (size_t i = 0; i < 16; i++)
    {
        printf("%02hhX ",header.e_ident[i]);
    }
    printf("\n%-40s%s\n","Class:",header.e_ident[EI_CLASS] ==ELFCLASS64?"ELF64":"ELF32");
    printf("%-40s%02hhX \n","Data:",header.e_ident[EI_DATA]);
    printf("%-40s%02hhX\n","Version:",header.e_ident[EI_VERSION] );    
    printf("%-40s%02hhX \n","ABI:",header.e_ident[EI_OSABI]);
    printf("%-40s%02hhX\n","ABI version:",header.e_ident[EI_ABIVERSION] );
    printf("%-40s","Type:");
    switch(header.e_type){
        case ET_REL:
            printf("ET_REL (Relocatable object file,library...\n");
            break;
        case ET_EXEC:
            printf("ET_EXEC (ELF executable file)\n");
             break;
        case ET_CORE:
            printf("ET_CORE (Core Dump)\n");
             break;
        case ET_NONE:
            printf("ET_NONE \n");
             break;
        case ET_DYN:
            printf("ET_DYN (Dynamic library)\n");
             break;
          default:
            printf("Other\n");
             break;
    }
  
    printf("%-40s%hu\n","Machine:",header.e_machine);
    printf("%-40s%d\n","Version:",header.e_version);
    printf("%-40s0x%X\n","Address of entry point:",header.e_entry);
    printf("%-40s%d\n","Start of segments: (offset)",header.e_phoff);
    printf("%-40s%d\n","Start of sections: (offset)",header.e_shoff);
    printf("%-40s0x%hX\n","Flags:",header.e_flags);
    printf("%-40s%d\n","This header size (bytes):",header.e_ehsize);
    printf("%-40s0x%hX\n","Flags:",header.e_flags);
    printf("%-40s%d\n","Size of segment headers:",header.e_phentsize);
    printf("%-40s%d\n","Number of segment headers:",header.e_phnum);
    printf("%-40s%d\n","Size of section headers:",header.e_shentsize);
    printf("%-40s%d\n","Number of section headers:",header.e_shnum);
    printf("%-40s%d\n","Section header string table index:",header.e_shstrndx);
    return header;
    
}



void parse_segment_header(Elf32_Ehdr header,char *fp){
   
    if(header.e_phnum == 0){
        printf("No segment headers\n");
        return;
    }
     printf("\nProgram headers:\n");
    printf("There are %d program headers starting at offset %d\n",header.e_phnum,header.e_phoff);
    
    printf("%-20s%-9s%-11s%-11s%-9s%-9s%-4s%-6s\n","Type","Offset","VirtAddr","PhysAddr","FileSiz","MemSiz","Flg","Align");

     for (uint16_t i = 0; i < header.e_phnum; i++){
          Elf32_Phdr *t = (Elf32_Phdr *)((char *)fp + (header.e_phoff+header.e_phentsize * i));
          
          
        izpisi(t, PT_NULL, "PT_NULL");
        izpisi(t, PT_LOAD, "PT_LOAD");
        izpisi(t, PT_DYNAMIC, "PT_DYNAMIC");
        izpisi(t, PT_INTERP, "PT_INTERP");
        izpisi(t, PT_NOTE, "PT_NOTE");
        izpisi(t, PT_SHLIB, "PT_SHLIB");
        izpisi(t, PT_PHDR, "PT_PHDR");
        izpisi(t, PT_TLS, "PT_TLS");
        izpisi(t, PT_NUM, "PT_NUM");
        izpisi(t, PT_LOOS, "PT_LOOS");
        izpisi(t, PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME");
        izpisi(t, PT_GNU_STACK, "PT_GNU_STACK");
        izpisi(t, PT_GNU_RELRO, "PT_GNU_RELRO");
        izpisi(t, PT_LOSUNW, "PT_LOSUNW");
        izpisi(t, PT_SUNWBSS, "PT_SUNWBSS");
        izpisi(t, PT_SUNWSTACK, "PT_SUNWSTACK");
        izpisi(t, PT_HISUNW, "PT_HISUNW");
        izpisi(t, PT_HIOS, "PT_HIOS");
        izpisi(t, PT_LOPROC, "PT_LOPROC");
        izpisi(t, PT_HIPROC, "PT_HIPROC");
       

         

     }
    

}

int izpisi2(int *c,int *b,char *fp,int off,uint16_t i,Elf32_Shdr *t,uint32_t v,const char* ime){
    if (t->sh_type == v) {  
         
    // printf("[%2d] %-22s%-17s%-9s%-7s%-7s%-3s%-4s%-3s%-4s%-3s\n",i,".tt","Type","Addr","Off","Size","ES","Flg","Lk","Inf","Al");
     printf("[%2d] ",i);
     
   
     printf("%-22s",fp+off+t->sh_name);
     printf("%-17s",ime);
    printf("%08X %06X %06X %02X ",t->sh_addr,t->sh_offset,t->sh_size,t->sh_entsize);
    (t->sh_flags&SHF_WRITE)?printf("W"):printf(" ");
    (t->sh_flags&SHF_ALLOC)?printf("A"):printf(" ");
    (t->sh_flags&SHF_EXECINSTR)?printf("E"):printf(" ");
    (t->sh_flags&SHF_MASKPROC)?printf("M"):printf(" ");
    printf(" ");
    printf("%02X %03X %1X\n",t->sh_link,t->sh_info,t->sh_addralign);
    if(!strcmp(".strtab",fp+off+t->sh_name)){
        *c+=i;
    }else{
        *c+=0;
    }

    if(!strcmp(".symtab",fp+off+t->sh_name)){
        *b+=i;
     }else{
        *b+=0;
     }
     
     if(!strcmp(".text",fp+off+t->sh_name)){
         return i;
     }else{
         return 0;
     }
    
     
    }
    *b+=0;
    return 0;

}
void izpisi_text(char *fp,int off,Elf32_Ehdr header){
       int o = (off*header.e_shentsize)+header.e_shoff;
       Elf32_Shdr *shd = (Elf32_Shdr*)(fp+o);
       int j = 1;
       printf("\nHex dump of .text section:\n");
       for(int i = 0;i<shd->sh_size;i++){
           printf("0x%02hhX ",*(shd->sh_offset+fp+i));
           if(j%4==0){
               printf("\n");
           }
           j++;


       }
}
void simbolna_tabela(char *fp,int off,int og,Elf32_Ehdr header){
        
 
       int o = (off*header.e_shentsize)+header.e_shoff;
       Elf32_Shdr *shd = (Elf32_Shdr*)(fp+o);

       int symbtab = (og*header.e_shentsize)+header.e_shoff;
       Elf32_Shdr *sh = (Elf32_Shdr*)(fp+symbtab);
       
       printf("\n\nSymbol table contains %d entries:\n",(sh->sh_size/sizeof(Elf32_Sym)));
       printf("%-5s%-8s%-6s%-5s\n","Num:","Value:","Size:","Name:");

       for(int i= 0;i<(sh->sh_size/sizeof(Elf32_Sym));i++){
           if(i>0){
               Elf32_Sym *ss =(Elf32_Sym*)(fp+sh->sh_offset+sizeof(Elf32_Sym)*i);
               
              printf("%2d: ",i);
              printf("%08X ",ss->st_value);
               printf("%04d ",ss->st_size);
               printf("%s\n",shd->sh_offset+fp+ss->st_name);

           }else
           {
               printf("%2d: ",i);
               printf("%08X ",0);
               printf("%04d \n",0);
           }
           
       }
     

}


void parse_section_headers(Elf32_Ehdr header,char *fp)
{
    if(!header.e_shnum){
        return;
    }
    printf("\nProgram section headers:\n");

     printf("There are %d segment headers starting at offset 0x%X\n",header.e_shnum,header.e_shoff);
    
    printf("[Nr] %-22s%-17s%-9s%-7s%-7s%-3s%-5s%-3s%-4s%-3s\n","Name","Type","Addr","Off","Size","ES","Flg","Lk","Inf","Al");
    
    int o = (header.e_shstrndx*header.e_shentsize)+header.e_shoff;
    Elf32_Shdr *shd = (Elf32_Shdr*)(fp+o);
    int off = shd->sh_offset;
    int a =0;
    int b = 0;
    int c = 0;
 
     for (uint16_t i = 0; i < header.e_shnum; i++){
          Elf32_Shdr *t = (Elf32_Shdr *)((char *)fp + (header.e_shoff+header.e_shentsize * i));
    
          
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_NULL, "NULL");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_SYMTAB, "SYMTAB");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_STRTAB, "STRTAB");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_RELA, "RELA");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_HASH, "HASH");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_DYNAMIC, "DYNAMIC");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_PROGBITS, "PROGBITS");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_NOTE, "NOTE");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_NOBITS, "NOBITS");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_REL, "REL");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_SHLIB, "SHLIB");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_DYNSYM, "DYNSYM");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_LOPROC, "LOPROC");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_HIPROC, "HIPROC");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_LOUSER, "LOUSER");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_HIUSER, "HIUSER");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_GNU_versym, "VERSYM");
        a+= izpisi2(&c,&b,fp,off,i,t, SHT_GNU_verneed, "VERNEED");
         

     }
    
    
    izpisi_text(fp,a,header);
   simbolna_tabela(fp,c,b,header);

}


int main(int argc,char* argv[]){
    if(argc!=2){
        puts("Uporaba elfdumb [ime_datoteke]\n");
        return EXIT_FAILURE;
    }
    
    struct stat st;
    stat(argv[1],&st);
    FILE *f = fopen(argv[1],"rb");
    if(!f)return EXIT_FAILURE;
    char *buf = malloc(st.st_size*sizeof(char));
    fread(buf,1,st.st_size,f);
   Elf32_Ehdr header =  parse_program_header(buf);
    parse_segment_header(header,buf);
    parse_section_headers(header,buf);
    
    fclose(f);
    free(buf);
    return EXIT_SUCCESS;
}