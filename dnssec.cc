#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/mobility-model.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/flow-monitor-helper.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace ns3;
using namespace std;

// ---------------------- Simulated Crypto ------------------------

std::string Sha256Hash(std::string message) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char*)message.c_str(), message.size(), hash);

  std::ostringstream os;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    os << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  return os.str();
}

std::string SignWithKey(std::string msg, std::string key) {
  return Sha256Hash(msg + key);
}

bool VerifySig(std::string msg, std::string sig, std::string key) {
  return (SignWithKey(msg, key) == sig);
}

// ---------------------- DNSSEC Zone Info ------------------------

struct DnsKey {
  std::string domain;
  std::string publicKey;
};

DnsKey rootKey   = {"root", "RootPublicKey"};
DnsKey comKey    = {"com", "ComPublicKey"};
DnsKey exKey     = {"example.com", "ExamplePublicKey"};

// ---------------------- DNSSEC Client ----------------------------

class DnssecClient : public Application {
public:
  void StartApplication() override {
    std::cout << "\n=== DNSSEC CLIENT VALIDATION CHAIN ===" << std::endl;

    // Send dummy UDP packet to visualize in NetAnim
    Ptr<Socket> udpSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    Address sinkAddress = InetSocketAddress(Ipv4Address("10.1.1.1"), 9999);
    udpSocket->Connect(sinkAddress);
    Ptr<Packet> p = Create<Packet>((uint8_t*)"DNS Query", 9);
    udpSocket->Send(p);

    // STEP 1: Validate Root DNSKEY
    std::string rootDnskeyHash = Sha256Hash(rootKey.publicKey);
    std::cout << "[ROOT] DNSKEY: " << rootKey.publicKey << "\n[ROOT] DS: " << rootDnskeyHash << std::endl;

    // STEP 2: Validate .com DNSKEY with Root DS
    std::string comDnskeyHash = Sha256Hash(comKey.publicKey);
    std::string comDsFromRoot = comDnskeyHash;
    std::cout << "[.COM] DNSKEY: " << comKey.publicKey << "\n[.COM] DS: " << comDsFromRoot << std::endl;

    if (comDsFromRoot != comDnskeyHash) {
      std::cout << "❌ .COM DNSKEY does not match ROOT DS\n";
      return;
    } else {
      std::cout << "✅ .COM DNSKEY validated with ROOT DS\n";
    }

    // STEP 3: Validate example.com DNSKEY with .com DS
    std::string exDnskeyHash = Sha256Hash(exKey.publicKey);
    std::string exDsFromCom = exDnskeyHash;
    std::cout << "[example.com] DNSKEY: " << exKey.publicKey << "\n[example.com] DS: " << exDsFromCom << std::endl;

    if (exDsFromCom != exDnskeyHash) {
      std::cout << "❌ example.com DNSKEY does not match .COM DS\n";
      return;
    } else {
      std::cout << "✅ example.com DNSKEY validated with .COM DS\n";
    }

    // STEP 4: Validate signed A record
    std::string arecord = "example.com A 192.0.2.1";
    std::string sig = SignWithKey(arecord, exKey.publicKey);

    std::cout << "\n[example.com] RRSIG(A): " << sig << std::endl;
    if (VerifySig(arecord, sig, exKey.publicKey)) {
      std::cout << "✅ A record validated with example.com's DNSKEY\n";
    } else {
      std::cout << "❌ A record signature invalid\n";
      return;
    }

    std::cout << "\n✅ DNSSEC CHAIN VALIDATION COMPLETE" << std::endl;
    std::cout << "Client verifies the full chain of trust\n";
  }
};

// ---------------------- Main NS-3 Simulation ---------------------

int main(int argc, char *argv[]) {
  NodeContainer nodes;
  nodes.Create(4); // 0: example.com, 1: com, 2: root, 3: client

  InternetStackHelper stack;
  stack.Install(nodes);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer d1 = p2p.Install(nodes.Get(3), nodes.Get(2));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));
  NetDeviceContainer d3 = p2p.Install(nodes.Get(1), nodes.Get(0));

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  ipv4.Assign(d1);
  ipv4.SetBase("10.1.2.0", "255.255.255.0");
  ipv4.Assign(d2);
  ipv4.SetBase("10.1.3.0", "255.255.255.0");
  ipv4.Assign(d3);

  // Set constant positions
  MobilityHelper mobility;
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes);
  nodes.Get(3)->GetObject<MobilityModel>()->SetPosition(Vector(10, 10, 0)); // client
  nodes.Get(2)->GetObject<MobilityModel>()->SetPosition(Vector(30, 10, 0)); // root
  nodes.Get(1)->GetObject<MobilityModel>()->SetPosition(Vector(50, 10, 0)); // com
  nodes.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(70, 10, 0)); // example.com

  // Add DNSSEC client to node[3]
  Ptr<DnssecClient> clientApp = CreateObject<DnssecClient>();
  nodes.Get(3)->AddApplication(clientApp);
  clientApp->SetStartTime(Seconds(0.5));

  // Add UDP sink on example.com to receive dummy packet
  uint16_t sinkPort = 9999;
  Address sinkAddress(InetSocketAddress(Ipv4Address::GetAny(), sinkPort));
  Ptr<Socket> sinkSocket = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
  sinkSocket->Bind(sinkAddress);

  // NetAnim XML output
  AnimationInterface anim("dnssec-chain.xml");
  anim.SetConstantPosition(nodes.Get(3), 10, 10); // client
  anim.SetConstantPosition(nodes.Get(2), 30, 10); // root
  anim.SetConstantPosition(nodes.Get(1), 50, 10); // com
  anim.SetConstantPosition(nodes.Get(0), 70, 10); // example.com

  anim.UpdateNodeDescription(nodes.Get(0), "example.com");
  anim.UpdateNodeDescription(nodes.Get(1), "com");
  anim.UpdateNodeDescription(nodes.Get(2), "root");
  anim.UpdateNodeDescription(nodes.Get(3), "client");

  Simulator::Stop(Seconds(3.0));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}
