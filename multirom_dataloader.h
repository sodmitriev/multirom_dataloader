#ifndef MULTIROM_DATALOADER_MULTIROM_DATALOADER_H
#define MULTIROM_DATALOADER_MULTIROM_DATALOADER_H

int generate_config();

int init_project(const char* password);

int store_previous_project(const char* password);

int extract_project(const char* branch_name, int use_ram, const char* password);

char** list_branches(const char* password);

#endif //MULTIROM_DATALOADER_MULTIROM_DATALOADER_H
