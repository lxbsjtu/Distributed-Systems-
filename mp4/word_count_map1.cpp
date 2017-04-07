//
// Created by lxb on 2016/12/1.
//


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <map>
#include <unordered_map>
#include<algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <mutex>
#include <chrono>
#include <sys/types.h>
#include <sys/uio.h>
#include <algorithm>


struct letter_only: std::ctype<char>
{
    letter_only(): std::ctype<char>(get_table()) {}

    static std::ctype_base::mask const* get_table()
    {
        static std::vector<std::ctype_base::mask>
                rc(std::ctype<char>::table_size,std::ctype_base::space);

        std::fill(&rc['A'], &rc['z'+1], std::ctype_base::alpha);
        return &rc[0];
    }
};
//vector<std::string> get_split_files() {
//    DIR *dir;
//    vector <std::string> split_file;
//    struct dirent *ent;
//    if ((dir = opendir("split/")) != NULL) {
//        /* print all the files and directories within directory */
//        while ((ent = readdir(dir)) != NULL) {
//            if (ent->d_name[0] == 'p') {
//                printf("%s\n", ent->d_name);
//                std::string file_name(ent->d_name);
//                split_file.push_back(file_name);
//            }
//        }
//        closedir(dir);
//    }
//    return split_file;
//}
int main() {

    std::unordered_map<std::string, int> wordCount;
    std::ifstream input;
    input.imbue(std::locale(std::locale(), new letter_only())); //enable reading only letters!

    char exec1[180];
    sprintf(exec1, "cat split/* >> split/temp_input");
    system(exec1);

    input.open("split/temp_input");
    std::string word;
    while (input >> word) {
        ++wordCount[word];
    }

    for (auto const &wc : wordCount) {
        std::string out_dir = "map_output/pref_" + wc.first;
        std::ofstream out(out_dir);
        out << wc.first << ' ' << wc.second << '\n';
        out.close();
    }

    char exec[180];
    sprintf(exec, "rm split/*");
    system(exec);
}