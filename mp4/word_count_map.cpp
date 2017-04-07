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
#include <algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <mutex>
#include <chrono>
#include <sys/types.h>
#include <sys/uio.h>
#include <algorithm>

using std::string;

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

int main(int argc, char *argv[]) {
    string mid = argv[1];
    int mid_v = std::stoi(mid);
    int total = std::stoi(argv[2]);
    string prefix = argv[3];

    std::vector<string> input_files;
    for(int i = 4; i < argc; i++) {
        input_files.emplace_back(argv[i]);
    }

    std::unordered_map<std::string, int> wordCount;
    std::ifstream input;
    input.imbue(std::locale(std::locale(), new letter_only())); //enable reading only letters!

    {
        char exec[254];
        sprintf(exec, "touch tmp_input");
        system(exec);
    }

    // split the input files!
    for(auto file: input_files) {
        char exec[254];
        sprintf(exec, "split -da 3 --lines=$((`wc -l < %s`/%d)) %s tmp_split.", file.c_str(), total, file.c_str());
        system(exec);

        // merge the part of split file that we're handling!
        sprintf(exec, "cat tmp_split.%03d >> tmp_input", mid_v);
        system(exec);
    }

    // perform map on the input file!
    input.open("tmp_input");
    std::string word;
    while (input >> word) {
        //std::cout << word;
        ++wordCount[word];
    }

    for (auto const &wc : wordCount) {
        std::string out_dir = "mapout/" + prefix + "_" + mid + "_" + wc.first;
        std::ofstream out(out_dir);
        out << wc.first << ' ' << wc.second << '\n';
        out.close();
    }

    // clean up
    {
        char exec[180];
        sprintf(exec, "rm tmp_input tmp_split.*");
        system(exec);
    }
}