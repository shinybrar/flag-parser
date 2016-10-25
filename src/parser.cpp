#include <boost/program_options.hpp>
using namespace boost::program_options;

#include <iostream>
using namespace std;


int main(int argc, char* argv[])
{
    try {
        string  destinationIpAddr;
        string  sourceIpAddr;
        string  dev;
        bool    createLog;
        int     sourcePort;
        int 	destinationPort;
        int     packetCount;    

        options_description desc("Allowed Options");
        desc.add_options()

        // First parameter describes option name/short name
        // The second is parameter to option
        // The third is description
        ("help,h", "Print Usage Message")
        ("dev,d", 	value(&dev),                "Interface to bind on, e.g eth0")
        ("smac,n", 	value(&sourceIpAddr),      	"Source IP Address, e.g. 192.168.175.0")
        ("dip,i", 	value(&destinationIpAddr),  "Destination IP Address e.g 192.168.175.0")
        ("sip,j",	value(&sourcePort),       	"Source Port data is coming from")
        ("prt,p", 	value(&destinationPort),    "Destination Port to parse data on, e.g 5555")
        ("cnt,c", 	value(&packetCount),        "Number of packets to parse")
        ("log,l", 	value(&createLog),         	"Create a log file - valid options - true,false,0,1")
        ;
    
        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {  
            cout << desc << "\n";
            return 0;
        }

        /*
        conflicting_options(vm, "output", "two");
        conflicting_options(vm, "output", "body");
        conflicting_options(vm, "output", "mainpackage");
        conflicting_options(vm, "two", "mainpackage");
        conflicting_options(vm, "body", "mainpackage");

        conflicting_options(vm, "two", "body");
        conflicting_options(vm, "libmakfile", "mainpackage");
        conflicting_options(vm, "libmakfile", "mainpackage");

        option_dependency(vm, "depends", "mainpackage");
        option_dependency(vm, "sources", "mainpackage");
        option_dependency(vm, "root", "mainpackage");

        cout << "two = " << vm["two"].as<bool>() << "\n";
        */
    }
    catch(exception& e) {
        cerr << e.what() << "\n";
    }
}
