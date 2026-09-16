#define private public
#include "directory.h"
#undef private
#define protected public
#include "orch.h"
#undef protected
#include "ut_helper.h"
#define private public
#define protected public
#include "neighorch.h"
#include "muxorch.h"
#include "fdborch.h"
#include "routeorch.h"
#include "crmorch.h"
#include "bfdorch.h"
#undef protected
#undef private
#include "mock_orchagent_main.h"
#include "mock_sai_api.h"
#include "mock_orch_test.h"
#include "nexthopkey.h"
#include "ipaddress.h"
#include "gtest/gtest.h"
#include <string>
#include <functional>
#include <algorithm>
#include <cstring>
#include <tuple>
#include "swssnet.h"
#include "subscriberstatetable.h"

EXTERN_MOCK_FNS
extern std::string gMySwitchType;
extern bool gMultiAsicVoq;

namespace mux_rollback_test
{
    DEFINE_SAI_API_MOCK(neighbor);
    DEFINE_SAI_API_MOCK_SPECIFY_ENTRY_WITH_SET(route, route);
    DEFINE_SAI_GENERIC_API_MOCK(acl, acl_entry);
    DEFINE_SAI_GENERIC_API_OBJECT_BULK_MOCK(next_hop, next_hop);
    DEFINE_SAI_GENERIC_API_MOCK(next_hop_group, next_hop_group_member);
    DEFINE_SAI_GENERIC_API_MOCK(bfd, bfd_session);
    using ::testing::_;
    using namespace std;
    using namespace mock_orch_test;
    using ::testing::Return;
    using ::testing::Throw;
    using ::testing::DoAll;
    using ::testing::SetArrayArgument;
    using ::testing::AtLeast;

    static const string TEST_INTERFACE = "Ethernet4";

    sai_bulk_create_neighbor_entry_fn old_create_neighbor_entries;
    sai_bulk_remove_neighbor_entry_fn old_remove_neighbor_entries;
    sai_bulk_create_route_entry_fn old_create_route_entries;
    sai_bulk_remove_route_entry_fn old_remove_route_entries;
    sai_bulk_set_route_entry_attribute_fn old_set_route_entries_attribute;
    sai_bulk_object_create_fn old_object_create;
    sai_bulk_object_remove_fn old_object_remove;
    static std::function<sai_status_t(const sai_route_entry_t*, const sai_attribute_t*)> route_set;
    static std::function<sai_status_t(sai_object_id_t, const sai_attribute_t*)> acl_set;
    static std::function<sai_status_t(sai_object_id_t, const sai_attribute_t*)> bfd_set;
    static std::function<sai_status_t(sai_object_id_t)> group_remove;
    static std::function<sai_status_t(sai_object_id_t, const sai_attribute_t*)> group_member_set;
    static std::function<sai_status_t(uint32_t, const sai_object_id_t*, sai_bulk_op_error_mode_t,
                                     sai_status_t*)> group_members_remove;
    static sai_bulk_object_remove_fn original_group_members_remove;

    static sai_status_t RemoveGroup(sai_object_id_t oid)
    {
        return group_remove ? group_remove(oid) : old_sai_next_hop_group_api->remove_next_hop_group(oid);
    }

    static sai_status_t SetGroupMember(sai_object_id_t oid, const sai_attribute_t* attr)
    {
        return group_member_set ? group_member_set(oid, attr)
                                : old_sai_next_hop_group_api->set_next_hop_group_member_attribute(oid, attr);
    }

    static sai_status_t RemoveGroupMembers(GENERIC_BULK_REMOVE_PARAMS(next_hop_group_member))
    {
        return group_members_remove ? group_members_remove(GENERIC_BULK_REMOVE_ARGS(next_hop_group_member))
                                    : original_group_members_remove(GENERIC_BULK_REMOVE_ARGS(next_hop_group_member));
    }

    static sai_status_t SetBfdSession(sai_object_id_t oid, const sai_attribute_t* attr)
    {
        return bfd_set ? bfd_set(oid, attr) : old_sai_bfd_api->set_bfd_session_attribute(oid, attr);
    }

    class BfdSessions
    {
    public:
        void Start(DBConnector* app, DBConnector* state)
        {
            INIT_SAI_API_MOCK(bfd);
            initialized_ = true;
            sai_bfd_api->set_bfd_session_attribute = SetBfdSession;
            previous_bgp_ = gDirectory.get<BgpGlobalStateOrch*>();
            gDirectory.m_values.erase(typeid(BgpGlobalStateOrch*).name());
            bgp_ = std::make_unique<BgpGlobalStateOrch>(app, "BGP_DEVICE_GLOBAL_TABLE");
            bgp_->bfd_offload = true;
            gDirectory.set(bgp_.get());
            bfd_ = std::make_unique<BfdOrch>(app, APP_BFD_SESSION_TABLE_NAME,
                TableConnector(state, STATE_BFD_SESSION_TABLE_NAME));
            gNeighOrch->attach(bfd_.get());
        }

        ~BfdSessions()
        {
            bfd_set = nullptr;
            if (bfd_)
            {
                vector<string> keys;
                for (const auto& session : bfd_->bfd_session_map)
                    keys.push_back(session.first);
                for (const auto& key : keys)
                    EXPECT_TRUE(bfd_->remove_bfd_session(key));
                bfd_.reset();
            }
            if (initialized_)
            {
                gDirectory.m_values.erase(typeid(BgpGlobalStateOrch*).name());
                if (previous_bgp_)
                    gDirectory.set(previous_bgp_);
                bgp_.reset();
                DEINIT_SAI_API_MOCK(bfd);
            }
        }

        void Add(const string& alias, const string& ip, const string& vrf = "default")
        {
            const auto key = vrf + ":" + alias + ":" + ip;
            auto consumer = bfd_->getConsumerBase(APP_BFD_SESSION_TABLE_NAME);
            consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND,
                vector<FieldValueTuple>{{"local_addr", "192.168.0.1"}, {"type", "async_active"}}));
            static_cast<Orch*>(bfd_.get())->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(key));
            ASSERT_EQ(1u, bfd_->bfd_inject_next_hop_lookup.count(key));
            keys_.push_back(key);
        }

        sai_object_id_t Id(size_t index)
        {
            return bfd_->bfd_inject_next_hop_lookup.at(keys_.at(index)).bfd_session_id;
        }

        void ExpectBinding(size_t index, sai_object_id_t oid)
        {
            EXPECT_EQ(oid, bfd_->bfd_inject_next_hop_lookup.at(keys_.at(index)).next_hop_id);
            sai_attribute_t attr{};
            attr.id = SAI_BFD_SESSION_ATTR_NEXT_HOP_ID;
            ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_bfd_api->get_bfd_session_attribute(Id(index), 1, &attr));
            EXPECT_EQ(oid, attr.value.oid);
        }

    private:
        bool initialized_ = false;
        BgpGlobalStateOrch* previous_bgp_ = nullptr;
        std::unique_ptr<BgpGlobalStateOrch> bgp_;
        std::unique_ptr<BfdOrch> bfd_;
        vector<string> keys_;
    };

    static sai_status_t SetSingleRoute(const sai_route_entry_t* entry, const sai_attribute_t* attr)
    {
        return route_set ? route_set(entry, attr)
                         : old_sai_route_api->set_route_entry_attribute(entry, attr);
    }

    static sai_status_t SetAclEntry(sai_object_id_t oid, const sai_attribute_t* attr)
    {
        return acl_set ? acl_set(oid, attr) : old_sai_acl_api->set_acl_entry_attribute(oid, attr);
    }

    class MuxRollbackTest : public MockOrchTest
    {
    protected:
        std::string m_neighbor_mode = "host-route";
        std::string m_server_prefix = SERVER_IP1 + "/32";
        bool m_second_cable = false;

        void SetMuxStateFromAppDb(std::string state, const string& port = TEST_INTERFACE)
        {
            Table mux_cable_table = Table(m_app_db.get(), APP_MUX_CABLE_TABLE_NAME);
            mux_cable_table.set(port, { { STATE, state } });
            m_MuxCableOrch->addExistingData(&mux_cable_table);
            static_cast<Orch *>(m_MuxCableOrch)->doTask();
        }

        void SetAndAssertMuxState(std::string state)
        {
            ASSERT_TRUE(m_MuxCable->setState(state));
            EXPECT_EQ(state, m_MuxCable->getState());
        }

        bool IsPrefixBasedMuxNeighbor()
        {
            NextHopKey nhKey = NextHopKey(IpAddress(SERVER_IP1), VLAN_1000);
            return gNeighOrch->isPrefixNeighborNh(nhKey);
        }

        void AddMissingMuxNeighbor(const IpAddress& missingNeighbor)
        {
            auto existingNeighbor = m_MuxCable->nbr_handler_->neighbors_.find(IpAddress(SERVER_IP1));
            ASSERT_NE(existingNeighbor, m_MuxCable->nbr_handler_->neighbors_.end());
            m_MuxCable->nbr_handler_->neighbors_[missingNeighbor] = existingNeighbor->second;

            ASSERT_EQ(gNeighOrch->m_syncdNeighbors.count(NeighborEntry(missingNeighbor, VLAN_1000)), 0u);
            ASSERT_FALSE(gNeighOrch->hasNextHop(NextHopKey(missingNeighbor, VLAN_1000)));
        }

        void ApplyInitialConfigs()
        {
            Table peer_switch_table = Table(m_config_db.get(), CFG_PEER_SWITCH_TABLE_NAME);
            Table decap_tunnel_table = Table(m_app_db.get(), APP_TUNNEL_DECAP_TABLE_NAME);
            Table decap_term_table = Table(m_app_db.get(), APP_TUNNEL_DECAP_TERM_TABLE_NAME);
            Table mux_cable_table = Table(m_config_db.get(), CFG_MUX_CABLE_TABLE_NAME);
            Table port_table = Table(m_app_db.get(), APP_PORT_TABLE_NAME);
            Table vlan_table = Table(m_app_db.get(), APP_VLAN_TABLE_NAME);
            Table vlan_member_table = Table(m_app_db.get(), APP_VLAN_MEMBER_TABLE_NAME);
            Table neigh_table = Table(m_app_db.get(), APP_NEIGH_TABLE_NAME);
            Table intf_table = Table(m_app_db.get(), APP_INTF_TABLE_NAME);

            auto ports = ut_helper::getInitialSaiPorts();
            port_table.set(TEST_INTERFACE, ports[TEST_INTERFACE]);
            if (m_second_cable)
                port_table.set("Ethernet8", ports["Ethernet8"]);
            port_table.set("PortConfigDone", { { "count", to_string(m_second_cable ? 2 : 1) } });
            port_table.set("PortInitDone", { {} });

            neigh_table.set(
                VLAN_1000 + neigh_table.getTableNameSeparator() + SERVER_IP1, { { "neigh", "62:f9:65:10:2f:04" },
                                                                               { "family", "IPv4" } });

            vlan_table.set(VLAN_1000, { { "admin_status", "up" },
                                        { "mtu", "9100" },
                                        { "mac", "00:aa:bb:cc:dd:ee" } });
            vlan_member_table.set(
                VLAN_1000 + vlan_member_table.getTableNameSeparator() + TEST_INTERFACE,
                { { "tagging_mode", "untagged" } });
            if (m_second_cable)
                vlan_member_table.set(VLAN_1000 + vlan_member_table.getTableNameSeparator() + "Ethernet8",
                                      {{"tagging_mode", "untagged"}});

            intf_table.set(VLAN_1000, { { "grat_arp", "enabled" },
                                        { "proxy_arp", "enabled" },
                                        { "mac_addr", "00:00:00:00:00:00" } });
            intf_table.set(
                VLAN_1000 + neigh_table.getTableNameSeparator() + "192.168.0.1/21", {
                                                                                        { "scope", "global" },
                                                                                        { "family", "IPv4" },
                                                                                    });

            decap_term_table.set(
                MUX_TUNNEL + neigh_table.getTableNameSeparator() + "2.2.2.2", { { "src_ip", "1.1.1.1" },
                                                                                { "term_type", "P2P" } });

            decap_tunnel_table.set(MUX_TUNNEL, { { "dscp_mode", "uniform" },
                                                 { "src_ip", "1.1.1.1" },
                                                 { "ecn_mode", "copy_from_outer" },
                                                 { "encap_ecn_mode", "standard" },
                                                 { "ttl_mode", "pipe" },
                                                 { "tunnel_type", "IPINIP" } });

            peer_switch_table.set(PEER_SWITCH_HOSTNAME, { { "address_ipv4", PEER_IPV4_ADDRESS } });

            mux_cable_table.set(TEST_INTERFACE, { { "server_ipv4", m_server_prefix },
                                                  { "server_ipv6", "a::a/128" },
                                                  { "neighbor_mode", m_neighbor_mode },
                                                  { "state", "auto" } });
            if (m_second_cable)
                mux_cable_table.set("Ethernet8", {{"server_ipv4", "192.168.1.2/32"},
                    {"server_ipv6", "b::a/128"}, {"neighbor_mode", m_neighbor_mode}, {"state", "auto"}});

            gPortsOrch->addExistingData(&port_table);
            gPortsOrch->addExistingData(&vlan_table);
            gPortsOrch->addExistingData(&vlan_member_table);
            static_cast<Orch *>(gPortsOrch)->doTask();

            gIntfsOrch->addExistingData(&intf_table);
            static_cast<Orch *>(gIntfsOrch)->doTask();

            m_TunnelDecapOrch->addExistingData(&decap_tunnel_table);
            m_TunnelDecapOrch->addExistingData(&decap_term_table);
            static_cast<Orch *>(m_TunnelDecapOrch)->doTask();

            m_MuxOrch->addExistingData(&peer_switch_table);
            static_cast<Orch *>(m_MuxOrch)->doTask();

            m_MuxOrch->addExistingData(&mux_cable_table);
            static_cast<Orch *>(m_MuxOrch)->doTask();

            gNeighOrch->addExistingData(&neigh_table);
            static_cast<Orch *>(gNeighOrch)->doTask();

            m_MuxCable = m_MuxOrch->getMuxCable(TEST_INTERFACE);

            // We always expect the mux to be initialized to standby
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }

        void PostSetUp() override
        {
            INIT_SAI_API_MOCK(neighbor);
            INIT_SAI_API_MOCK(route);
            INIT_SAI_API_MOCK(acl);
            INIT_SAI_API_MOCK(next_hop);
            INIT_SAI_API_MOCK(next_hop_group);
            MockSaiApis();
            sai_route_api->set_route_entry_attribute = SetSingleRoute;
            sai_acl_api->set_acl_entry_attribute = SetAclEntry;
            sai_next_hop_group_api->remove_next_hop_group = RemoveGroup;
            sai_next_hop_group_api->set_next_hop_group_member_attribute = SetGroupMember;
            original_group_members_remove = gRouteOrch->gNextHopGroupMemberBulker.remove_entries;
            gRouteOrch->gNextHopGroupMemberBulker.remove_entries = RemoveGroupMembers;
            old_create_neighbor_entries = gNeighOrch->gNeighBulker.create_entries;
            old_remove_neighbor_entries = gNeighOrch->gNeighBulker.remove_entries;
            old_object_create = gNeighOrch->gNextHopBulker.create_entries;
            old_object_remove = gNeighOrch->gNextHopBulker.remove_entries;
            old_create_route_entries = m_MuxCable->nbr_handler_->gRouteBulker.create_entries;
            old_remove_route_entries = m_MuxCable->nbr_handler_->gRouteBulker.remove_entries;
            old_set_route_entries_attribute = m_MuxCable->nbr_handler_->gRouteBulker.set_entries_attribute;
            gNeighOrch->gNeighBulker.create_entries = mock_create_neighbor_entries;
            gNeighOrch->gNeighBulker.remove_entries = mock_remove_neighbor_entries;
            gNeighOrch->gNextHopBulker.create_entries = mock_create_next_hops;
            gNeighOrch->gNextHopBulker.remove_entries = mock_remove_next_hops;
            m_MuxCable->nbr_handler_->gRouteBulker.create_entries = mock_create_route_entries;
            m_MuxCable->nbr_handler_->gRouteBulker.remove_entries = mock_remove_route_entries;
            m_MuxCable->nbr_handler_->gRouteBulker.set_entries_attribute = mock_set_route_entries_attribute;
        }

        void PreTearDown() override
        {
            route_set = {};
            acl_set = {};
            group_remove = {};
            group_member_set = {};
            group_members_remove = {};
            gRouteOrch->gNextHopGroupMemberBulker.remove_entries = original_group_members_remove;
            RestoreSaiApis();
            DEINIT_SAI_API_MOCK(next_hop_group);
            DEINIT_SAI_API_MOCK(next_hop);
            DEINIT_SAI_API_MOCK(acl);
            DEINIT_SAI_API_MOCK(route);
            DEINIT_SAI_API_MOCK(neighbor);
            gNeighOrch->gNeighBulker.create_entries = old_create_neighbor_entries;
            gNeighOrch->gNeighBulker.remove_entries = old_remove_neighbor_entries;
            gNeighOrch->gNextHopBulker.create_entries = old_object_create;
            gNeighOrch->gNextHopBulker.remove_entries = old_object_remove;
            if (m_MuxOrch->isMuxExists(TEST_INTERFACE))
            {
                auto cable = m_MuxOrch->getMuxCable(TEST_INTERFACE);
                cable->nbr_handler_->gRouteBulker.create_entries = old_create_route_entries;
                cable->nbr_handler_->gRouteBulker.remove_entries = old_remove_route_entries;
                cable->nbr_handler_->gRouteBulker.set_entries_attribute = old_set_route_entries_attribute;
            }
        }
    };

    class MuxRollbackPrefixRouteTest : public MuxRollbackTest
    {
    public:
        MuxRollbackPrefixRouteTest()
        {
            m_neighbor_mode = "prefix-route";
        }
    };

    TEST_F(MuxRollbackTest, StandbyToActiveNeighborAlreadyExists)
    {
        if (!IsPrefixBasedMuxNeighbor())
        {
            std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_ALREADY_EXISTS};
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
                .WillOnce(DoAll(SetArrayArgument<5>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_ALREADY_EXISTS)));
        }
        SetAndAssertMuxState(ACTIVE_STATE);
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyNeighborNotFound)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_NOT_FOUND};
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                .WillOnce(DoAll(SetArrayArgument<3>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_NOT_FOUND)));
        }
        SetAndAssertMuxState(STANDBY_STATE);
    }

    TEST_F(MuxRollbackTest, StandbyToActiveMissingNeighborPropagatesFailure)
    {
        IpAddress missingNeighbor("192.168.0.3");
        AddMissingMuxNeighbor(missingNeighbor);
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops).Times(0);
        NeighborEntry existingNeighbor(IpAddress(SERVER_IP1), VLAN_1000);
        NextHopKey existingNextHop(IpAddress(SERVER_IP1), VLAN_1000);

        SetMuxStateFromAppDb(ACTIVE_STATE);

        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(1u, m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME)->m_toSync.count(TEST_INTERFACE));
        EXPECT_FALSE(gNeighOrch->isHwConfigured(existingNeighbor));
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(existingNextHop), SAI_NULL_OBJECT_ID);
        EXPECT_EQ(gNeighOrch->m_syncdNeighbors.count(NeighborEntry(missingNeighbor, VLAN_1000)), 0u);
        EXPECT_EQ(
            gNeighOrch->getLocalNextHopId(NextHopKey(missingNeighbor, VLAN_1000)),
            SAI_NULL_OBJECT_ID);
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyMissingNeighborPropagatesFailure)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        IpAddress missingNeighbor("192.168.0.3");
        AddMissingMuxNeighbor(missingNeighbor);
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
        NeighborEntry existingNeighbor(IpAddress(SERVER_IP1), VLAN_1000);
        NextHopKey existingNextHop(IpAddress(SERVER_IP1), VLAN_1000);

        SetMuxStateFromAppDb(STANDBY_STATE);

        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_TRUE(gNeighOrch->isHwConfigured(existingNeighbor));
        EXPECT_NE(gNeighOrch->getLocalNextHopId(existingNextHop), SAI_NULL_OBJECT_ID);
        EXPECT_EQ(m_MuxCable->nbr_handler_->neighbors_.at(IpAddress(SERVER_IP1)),
                  gNeighOrch->getLocalNextHopId(existingNextHop));
        EXPECT_EQ(gNeighOrch->m_syncdNeighbors.count(NeighborEntry(missingNeighbor, VLAN_1000)), 0u);
        EXPECT_EQ(
            gNeighOrch->getLocalNextHopId(NextHopKey(missingNeighbor, VLAN_1000)),
            SAI_NULL_OBJECT_ID);
    }

    TEST_F(MuxRollbackTest, StandbyToActiveRouteNotFound)
    {
        std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_NOT_FOUND};
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_route_api, remove_route_entries)
                .WillOnce(DoAll(SetArrayArgument<3>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_NOT_FOUND)));
        }
        SetAndAssertMuxState(ACTIVE_STATE);
    }

    TEST_F(MuxRollbackPrefixRouteTest, StandbyToActiveSetRouteAttrNotFoundRollbackToStandby)
    {
        std::vector<sai_status_t> exp_status_not_found{SAI_STATUS_ITEM_NOT_FOUND};
        std::vector<sai_status_t> exp_status_success{SAI_STATUS_SUCCESS};
        EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
            .WillOnce(DoAll(SetArrayArgument<4>(exp_status_not_found.begin(), exp_status_not_found.end()),
                            Return(SAI_STATUS_ITEM_NOT_FOUND)))
            .WillOnce(DoAll(SetArrayArgument<4>(exp_status_success.begin(), exp_status_success.end()),
                            Return(SAI_STATUS_SUCCESS)));
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyRouteAlreadyExists)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_ALREADY_EXISTS};

        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_route_api, create_route_entries)
                .WillOnce(DoAll(SetArrayArgument<5>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_ALREADY_EXISTS)));
        }
        SetAndAssertMuxState(STANDBY_STATE);
    }

    TEST_F(MuxRollbackTest, StandbyToActiveAclNotFound)
    {
        EXPECT_CALL(*mock_sai_acl_api, remove_acl_entry)
            .WillOnce(Return(SAI_STATUS_ITEM_NOT_FOUND));
        SetAndAssertMuxState(ACTIVE_STATE);
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyAclAlreadyExists)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        EXPECT_CALL(*mock_sai_acl_api, create_acl_entry)
            .WillOnce(Return(SAI_STATUS_ITEM_ALREADY_EXISTS));
        SetAndAssertMuxState(STANDBY_STATE);
    }

    TEST_F(MuxRollbackTest, NextHopAlreadyExistsWithoutOidDoesNotSucceed)
    {
        if (!IsPrefixBasedMuxNeighbor())
        {
            std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_ALREADY_EXISTS};
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                .WillOnce(DoAll(SetArrayArgument<6>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_ALREADY_EXISTS)));
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(NextHopKey(IpAddress(SERVER_IP1), VLAN_1000)));
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyNextHopNotFound)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        if (!IsPrefixBasedMuxNeighbor())
        {
            std::vector<sai_status_t> exp_status{SAI_STATUS_ITEM_NOT_FOUND};
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
                .WillOnce(DoAll(SetArrayArgument<3>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_ITEM_NOT_FOUND)));
        }
        SetAndAssertMuxState(STANDBY_STATE);
    }

    TEST_F(MuxRollbackTest, StandbyToActiveRuntimeErrorRollbackToStandby)
    {
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_route_api, remove_route_entries)
                .WillOnce(Throw(runtime_error("Mock runtime error")));
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to standby
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyRuntimeErrorRollbackToActive)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_route_api, create_route_entries)
                .WillOnce(Throw(runtime_error("Mock runtime error")));
        }
        SetMuxStateFromAppDb(STANDBY_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to active
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, StandbyToActiveLogicErrorRollbackToStandby)
    {
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
                .WillOnce(Throw(logic_error("Mock logic error")));
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to standby
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyLogicErrorRollbackToActive)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                .WillOnce(Throw(logic_error("Mock logic error")));
        }
        SetMuxStateFromAppDb(STANDBY_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to active
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, StandbyToActiveExceptionRollbackToStandby)
    {
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                .WillOnce(Throw(exception()));
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to standby
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, ActiveToStandbyExceptionRollbackToActive)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
                .WillOnce(Throw(exception()));
        }
        SetMuxStateFromAppDb(STANDBY_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to active
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
    }

    TEST_F(MuxRollbackTest, StandbyToActiveNextHopTableFullRollbackToActive)
    {
        std::vector<sai_status_t> exp_status{SAI_STATUS_TABLE_FULL};
        if (!IsPrefixBasedMuxNeighbor())
        {
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                .WillOnce(DoAll(SetArrayArgument<6>(exp_status.begin(), exp_status.end()), Return(SAI_STATUS_TABLE_FULL)));
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        if (IsPrefixBasedMuxNeighbor())
        {
            // With prefix-based neighbors, state transition should succeed
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        }
        else
        {
            // Without prefix-based neighbors, expect rollback to standby
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        }
    }

    class MuxHybridTest : public MuxRollbackTest
    {
    protected:
        MuxHybridTest()
        {
            m_server_prefix = "192.168.0.0/24";
        }

        void PostSetUp() override
        {
            MuxRollbackTest::PostSetUp();
            Port vlan;
            ASSERT_TRUE(gPortsOrch->getPort(VLAN_1000, vlan));
            vlan.m_oper_status = SAI_PORT_OPER_STATUS_UP;
            gPortsOrch->setPort(VLAN_1000, vlan);
            if (gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)) != SAI_NULL_OBJECT_ID)
            {
                ASSERT_TRUE(gNeighOrch->clearNextHopFlag(Key(SERVER_IP1), NHFLAGS_IFDOWN));
            }
        }

        NextHopKey Key(const string& ip)
        {
            return NextHopKey(IpAddress(ip), VLAN_1000);
        }

        void NeighborEvent(const string& ip, bool add = true, const string& mac = MAC4)
        {
            auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
            string key = VLAN_1000 + ":" + ip;
            vector<FieldValueTuple> fields{{"neigh", mac}, {"family", IpAddress(ip).isV4() ? "IPv4" : "IPv6"}};
            consumer->addToSync(KeyOpFieldsValuesTuple(key, add ? SET_COMMAND : DEL_COMMAND, fields));
            static_cast<Orch*>(gNeighOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(key));
        }

        void ThreeNeighbors()
        {
            NeighborEvent("192.168.0.3");
            NeighborEvent("192.168.0.4");
            for (const auto& ip : {SERVER_IP1, string("192.168.0.3"), string("192.168.0.4")})
            {
                ASSERT_EQ(1u, gNeighOrch->getNeighborTable().count(Key(ip)));
                ASSERT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(ip)));
                ASSERT_EQ(1u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress(ip)));
                if (gNeighOrch->getLocalNextHopId(Key(ip)) != SAI_NULL_OBJECT_ID)
                {
                    ASSERT_TRUE(gNeighOrch->clearNextHopFlag(Key(ip), NHFLAGS_IFDOWN));
                }
            }
        }

        sai_neighbor_entry_t SaiNeighbor(const string& ip)
        {
            sai_neighbor_entry_t entry{};
            entry.switch_id = gSwitchId;
            entry.rif_id = gIntfsOrch->getRouterIntfsId(VLAN_1000);
            copy(entry.ip_address, IpAddress(ip));
            return entry;
        }

        sai_route_entry_t SaiRoute(const string& prefix)
        {
            sai_route_entry_t entry{};
            entry.switch_id = gSwitchId;
            entry.vr_id = gVirtualRouterId;
            copy(entry.destination, IpPrefix(prefix));
            return entry;
        }

        sai_object_id_t RouteNextHop(const string& prefix)
        {
            auto route = SaiRoute(prefix);
            sai_attribute_t attr{};
            attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
            EXPECT_EQ(SAI_STATUS_SUCCESS, old_sai_route_api->get_route_entry_attribute(&route, 1, &attr));
            return attr.value.oid;
        }

        void ExpectNeighborHardware(const string& ip, bool present)
        {
            auto entry = SaiNeighbor(ip);
            sai_attribute_t attr{};
            attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
            auto status = old_sai_neighbor_api->get_neighbor_entry_attribute(&entry, 1, &attr);
            if (present)
            {
                EXPECT_EQ(SAI_STATUS_SUCCESS, status) << ip;
            }
            else
            {
                EXPECT_EQ(SAI_STATUS_ITEM_NOT_FOUND, status) << ip;
            }
        }

        void ExpectRemovedNextHop(sai_object_id_t oid)
        {
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_ATTR_TYPE;
            EXPECT_NE(SAI_STATUS_SUCCESS, old_sai_next_hop_api->get_next_hop_attribute(oid, 1, &attr));
        }

        int RifRefs()
        {
            return gIntfsOrch->getSyncdIntfses().at(VLAN_1000).ref_count;
        }

        map<pair<int, string>, uint32_t> CrmUsed()
        {
            map<pair<int, string>, uint32_t> used;
            for (const auto& resource : gCrmOrch->m_resourcesMap)
                for (const auto& counter : resource.second.countersMap)
                    if (counter.second.usedCounter)
                        used[{static_cast<int>(resource.first), counter.first}] = counter.second.usedCounter;
            return used;
        }

        void RecoveryDue()
        {
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::time_point{};
        }

        void DispatchMux()
        {
            static_cast<Orch*>(m_MuxCableOrch)->doTask();
        }

        void RecoveryTimerTick()
        {
            for (auto selectable : m_MuxCableOrch->getSelectables())
            {
                auto executor = dynamic_cast<Executor*>(selectable);
                if (executor && executor->getName() == "MUX_RECOVERY_TIMER")
                {
                    executor->execute();
                    return;
                }
            }
            FAIL() << "Recovery timer must be registered with the dispatcher";
        }

        size_t PendingMuxRequest()
        {
            return m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME)->m_toSync.count(TEST_INTERFACE);
        }

        void HoldFirstEnableCleanup(bool& blocked, int& creates, int& removals)
        {
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                .WillRepeatedly([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                    if (++creates == 1)
                    {
                        for (uint32_t i = 0; i < object_count; ++i)
                        {
                            object_id[i] = SAI_NULL_OBJECT_ID;
                            object_statuses[i] = SAI_STATUS_TABLE_FULL;
                        }
                        return SAI_STATUS_FAILURE;
                    }
                    return old_sai_next_hop_api->create_next_hops(GENERIC_BULK_CREATE_ARGS(next_hop));
                });
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
                .WillRepeatedly([&](const sai_neighbor_entry_t* entry) -> sai_status_t {
                    ++removals;
                    return blocked ? SAI_STATUS_FAILURE : old_sai_neighbor_api->remove_neighbor_entry(entry);
                });
        }

        void HoldActiveNeighborRecovery(bool& blocked, int& attempts)
        {
            ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
            if (IsPrefixBasedMuxNeighbor())
            {
                EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
                    .WillRepeatedly([&](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                        ++attempts;
                        if (blocked)
                        {
                            for (uint32_t i = 0; i < object_count; ++i)
                                object_statuses[i] = SAI_STATUS_FAILURE;
                            return SAI_STATUS_FAILURE;
                        }
                        return old_sai_route_api->set_route_entries_attribute(SET_BULK_ATTR_ARGS(route));
                    });
            }
            else
            {
                EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                    .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                        for (uint32_t i = 0; i < object_count; ++i)
                            object_statuses[i] = SAI_STATUS_FAILURE;
                        return SAI_STATUS_FAILURE;
                    });
                EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                    .WillRepeatedly([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                        ++attempts;
                        if (blocked)
                        {
                            for (uint32_t i = 0; i < object_count; ++i)
                            {
                                object_id[i] = SAI_NULL_OBJECT_ID;
                                object_statuses[i] = SAI_STATUS_TABLE_FULL;
                            }
                            return SAI_STATUS_FAILURE;
                        }
                        return old_sai_next_hop_api->create_next_hops(GENERIC_BULK_CREATE_ARGS(next_hop));
                    });
            }
            SetMuxStateFromAppDb(STANDBY_STATE);
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
            testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
            SetMuxStateFromAppDb(ACTIVE_STATE);
        }

        void ExerciseActiveNeighborRetirement(bool readd, bool changed_mac)
        {
            SetAndAssertMuxState(ACTIVE_STATE);
            auto original = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1));
            bool blocked = true;
            int attempts = 0;
            ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
            NeighborEvent(SERVER_IP1, false);
            ASSERT_TRUE(original.incarnation->retired);
            ASSERT_EQ(0u, gNeighOrch->getNeighborTable().count(Key(SERVER_IP1)));
            ASSERT_TRUE(m_MuxCable->nbr_handler_->neighbors_.empty());
            if (readd)
            {
                NeighborEvent(SERVER_IP1, true, changed_mac ? MAC5 : original.mac.to_string());
                ASSERT_NE(original.incarnation, gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation);
            }
            int refs = RifRefs();
            auto crm = CrmUsed();
            auto replacement = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
            int prior_attempts = attempts;
            blocked = false;
            RecoveryDue();
            DispatchMux();
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(prior_attempts, attempts);
            EXPECT_EQ(refs, RifRefs());
            EXPECT_EQ(crm, CrmUsed());
            EXPECT_EQ(replacement, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
            EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
            EXPECT_TRUE(m_MuxCable->nbr_handler_->transition_.empty());
            ExpectNeighborHardware(SERVER_IP1, readd);
            if (readd)
            {
                auto entry = SaiNeighbor(SERVER_IP1);
                sai_attribute_t attr{};
                attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
                ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_neighbor_api->get_neighbor_entry_attribute(&entry, 1, &attr));
                EXPECT_EQ(changed_mac ? MacAddress(MAC5) : original.mac, MacAddress(attr.value.mac));
                EXPECT_EQ(0, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
            }
            else
            {
                auto entry = SaiRoute(SERVER_IP1);
                sai_attribute_t attr{};
                attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
                EXPECT_EQ(SAI_STATUS_ITEM_NOT_FOUND, old_sai_route_api->get_route_entry_attribute(&entry, 1, &attr));
            }
            DispatchMux();
            EXPECT_EQ(0u, PendingMuxRequest());
            RecoveryTimerTick();
            SetMuxStateFromAppDb(STANDBY_STATE);
            ASSERT_EQ(STANDBY_STATE, m_MuxCable->getState());
            SetMuxStateFromAppDb(ACTIVE_STATE);
            EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(refs, RifRefs());
            EXPECT_EQ(crm, CrmUsed());
            EXPECT_EQ(readd ? 1u : 0u, gNeighOrch->getNeighborTable().count(Key(SERVER_IP1)));
        }

        void ExerciseStandbyNeighborRetirement(bool readd, bool changed_mac)
        {
            auto original = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1));
            bool blocked = true;
            int creates = 0;
            int removes = 0;
            HoldFirstEnableCleanup(blocked, creates, removes);
            SetMuxStateFromAppDb(ACTIVE_STATE);
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
            SetMuxStateFromAppDb(STANDBY_STATE);
            blocked = false;
            NeighborEvent(SERVER_IP1, false);
            ASSERT_TRUE(original.incarnation->retired);
            if (readd)
            {
                NeighborEvent(SERVER_IP1, true, changed_mac ? MAC5 : original.mac.to_string());
                EXPECT_NE(original.incarnation, gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation);
            }
            auto crm = CrmUsed();
            int refs = RifRefs();
            int prior_removes = removes;
            RecoveryDue();
            DispatchMux();
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(prior_removes, removes);
            EXPECT_EQ(1, creates);
            EXPECT_EQ(refs, RifRefs());
            EXPECT_EQ(crm, CrmUsed());
            EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
            EXPECT_EQ(readd ? 1u : 0u, gNeighOrch->getNeighborTable().count(Key(SERVER_IP1)));
            ExpectNeighborHardware(SERVER_IP1, false);
            DispatchMux();
            EXPECT_EQ(0u, PendingMuxRequest());
            RecoveryTimerTick();
            SetMuxStateFromAppDb(ACTIVE_STATE);
            ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
            SetMuxStateFromAppDb(STANDBY_STATE);
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(refs, RifRefs());
            EXPECT_EQ(crm, CrmUsed());
        }

        void DeleteRoute(const string& prefix)
        {
            auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            consumer->addToSync(KeyOpFieldsValuesTuple(prefix, DEL_COMMAND, vector<FieldValueTuple>{}));
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        }

        void AddEcmpRoute(const string& prefix)
        {
            auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            vector<FieldValueTuple> fields{{"nexthop", SERVER_IP1 + ",192.168.0.3"},
                                          {"ifname", VLAN_1000 + "," + VLAN_1000}};
            consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND, fields));
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
            ASSERT_EQ(2u, gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix(prefix)).getSize());
        }

        void CompleteRecovery()
        {
            RecoveryDue();
            DispatchMux();
            ASSERT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_TRUE(m_MuxCable->nbr_handler_->transition_.empty());
            EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
            DispatchMux();
            EXPECT_EQ(0u, PendingMuxRequest());
            RecoveryTimerTick();
            EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
        }

        void RoundTripActive()
        {
            SetMuxStateFromAppDb(STANDBY_STATE);
            ASSERT_EQ(STANDBY_STATE, m_MuxCable->getState());
            ASSERT_FALSE(m_MuxCable->isStateChangeFailed());
            SetMuxStateFromAppDb(ACTIVE_STATE);
            ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
            ASSERT_FALSE(m_MuxCable->isStateChangeFailed());
        }

        void HoldRouteRecovery(const string& prefix, bool& blocked, int& restores)
        {
            auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
            route_set = [prefix, tunnel, &blocked, &restores](const sai_route_entry_t* entry,
                                                           const sai_attribute_t* attr) -> sai_status_t {
                if (sai_serialize_ip_prefix(entry->destination) == prefix &&
                    attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID && attr->value.oid != tunnel)
                {
                    ++restores;
                    if (blocked)
                        return SAI_STATUS_FAILURE;
                }
                return old_sai_route_api->set_route_entry_attribute(entry, attr);
            };
            if (IsPrefixBasedMuxNeighbor())
            {
                EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
                    .WillOnce([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                        for (uint32_t i = 0; i < object_count; ++i)
                            object_statuses[i] = SAI_STATUS_FAILURE;
                        return SAI_STATUS_FAILURE;
                    })
                    .WillRepeatedly([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                        return old_sai_route_api->set_route_entries_attribute(SET_BULK_ATTR_ARGS(route));
                    });
            }
            else
            {
                EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                    .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                        for (uint32_t i = 0; i < object_count; ++i)
                            object_statuses[i] = SAI_STATUS_FAILURE;
                        return SAI_STATUS_FAILURE;
                    });
            }
            SetMuxStateFromAppDb(STANDBY_STATE);
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
            ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
            ASSERT_EQ(tunnel, RouteNextHop(prefix));
            testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
            SetMuxStateFromAppDb(ACTIVE_STATE);
        }

        void SetFdb(const string& mac, const string& port)
        {
            auto consumer = gFdbOrch->getConsumerBase(APP_FDB_TABLE_NAME);
            ASSERT_NE(nullptr, consumer);
            string key = VLAN_1000 + ":" + mac;
            consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND,
                vector<FieldValueTuple>{{"port", port}, {"type", "dynamic"}}));
            static_cast<Orch*>(gFdbOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(key));
            string actual;
            ASSERT_TRUE(m_MuxOrch->getMuxPort(MacAddress(mac), VLAN_1000, actual));
            EXPECT_EQ(port, actual);
        }

        void MuxConfig(const string& port, bool add, const string& mode = "host-route")
        {
            vector<FieldValueTuple> fields;
            if (add)
                fields = {{"server_ipv4", port == TEST_INTERFACE ? m_server_prefix : "192.168.1.2/32"},
                          {"server_ipv6", port == TEST_INTERFACE ? "a::a/128" : "b::a/128"},
                          {"neighbor_mode", mode}, {"state", "auto"}};
            auto consumer = m_MuxOrch->getConsumerBase(CFG_MUX_CABLE_TABLE_NAME);
            consumer->addToSync(KeyOpFieldsValuesTuple(port, add ? SET_COMMAND : DEL_COMMAND, fields));
            static_cast<Orch*>(m_MuxOrch)->doTask();
        }

        void ConfigureFg(const string& prefix, const string& ip = SERVER_IP1)
        {
            const vector<pair<string, KeyOpFieldsValuesTuple>> operations{
                {CFG_FG_NHG, KeyOpFieldsValuesTuple("mux-recovery-fg", SET_COMMAND,
                    vector<FieldValueTuple>{{"bucket_size", "8"}, {"match_mode", "route-based"}})},
                {CFG_FG_NHG_MEMBER, KeyOpFieldsValuesTuple(ip, SET_COMMAND,
                    vector<FieldValueTuple>{{"FG_NHG", "mux-recovery-fg"}, {"bank", "0"}})},
                {CFG_FG_NHG_PREFIX, KeyOpFieldsValuesTuple(prefix, SET_COMMAND,
                    vector<FieldValueTuple>{{"FG_NHG", "mux-recovery-fg"}})}
            };
            for (const auto& operation : operations)
            {
                auto consumer = gFgNhgOrch->getConsumerBase(operation.first);
                ASSERT_NE(nullptr, consumer);
                consumer->addToSync(operation.second);
                static_cast<Orch*>(gFgNhgOrch)->doTask();
                ASSERT_EQ(0u, consumer->m_toSync.size());
            }
        }

        void ExpectFgNextHop(const string& prefix, sai_object_id_t target)
        {
            ASSERT_TRUE(gFgNhgOrch->syncdContainsFgNhg(gVirtualRouterId, IpPrefix(prefix)));
            const auto& fg = gFgNhgOrch->m_syncdFGRouteTables.at(gVirtualRouterId).at(IpPrefix(prefix));
            ASSERT_FALSE(fg.nhopgroup_members.empty());
            for (auto member : fg.nhopgroup_members)
            {
                sai_attribute_t attr{};
                attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
                ASSERT_EQ(SAI_STATUS_SUCCESS,
                    old_sai_next_hop_group_api->get_next_hop_group_member_attribute(member, 1, &attr));
                EXPECT_EQ(target, attr.value.oid);
            }
        }

        vector<FieldValueTuple> TableFields(Table& table)
        {
            vector<FieldValueTuple> fields;
            table.get(TEST_INTERFACE, fields);
            sort(fields.begin(), fields.end());
            return fields;
        }

        void NoProgramming()
        {
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries).Times(0);
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries).Times(0);
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry).Times(0);
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).Times(0);
            EXPECT_CALL(*mock_sai_route_api, create_route_entries).Times(0);
            EXPECT_CALL(*mock_sai_route_api, remove_route_entries).Times(0);
            EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute).Times(0);
            EXPECT_CALL(*mock_sai_route_api, create_route_entry).Times(0);
            EXPECT_CALL(*mock_sai_route_api, remove_route_entry).Times(0);
            EXPECT_CALL(*mock_sai_acl_api, create_acl_entry).Times(0);
            EXPECT_CALL(*mock_sai_acl_api, remove_acl_entry).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member).Times(0);
            route_set = [](const sai_route_entry_t*, const sai_attribute_t*) -> sai_status_t {
                ADD_FAILURE() << "Preflight rejection must not program routes";
                return SAI_STATUS_FAILURE;
            };
        }

        void AddRoute(const string& prefix, const string& ip)
        {
            auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            vector<FieldValueTuple> fields{{"nexthop", ip}, {"ifname", VLAN_1000}};
            consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND, fields));
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        }

        void ExpectStandbyRestored(int refs)
        {
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
            EXPECT_NE(nullptr, m_MuxCable->acl_handler_);
            EXPECT_EQ(refs, RifRefs());
            for (const auto& neighbor : m_MuxCable->nbr_handler_->neighbors_)
            {
                auto ip = neighbor.first.to_string();
                EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(ip)));
                EXPECT_FALSE(gNeighOrch->isHwConfigured(Key(ip)));
                EXPECT_EQ(neighbor.second, RouteNextHop(ip));
                EXPECT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(ip)));
                ExpectNeighborHardware(ip, false);
            }
        }
    };

    class MuxPrefixRecoveryTest : public MuxHybridTest
    {
    protected:
        MuxPrefixRecoveryTest() { m_neighbor_mode = "prefix-route"; }
    };

    class MuxSharedCableTest : public MuxHybridTest
    {
    protected:
        MuxSharedCableTest() { m_second_cable = true; }

        void PostSetUp() override
        {
            MuxHybridTest::PostSetUp();
            NeighborEvent("192.168.1.2", true, MAC5);
            ASSERT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key("192.168.1.2")));
            ASSERT_NE(nullptr, gAclOrch->getAclRule(INGRESS_TABLE_DROP, "mux_acl_rule"));
            ASSERT_EQ(2u, SoftwareAclPorts().size());
        }

        sai_object_id_t PortOid(const string& name)
        {
            Port port;
            EXPECT_TRUE(gPortsOrch->getPort(name, port));
            return port.m_port_id;
        }

        AclRule* SharedRule()
        {
            auto rule = gAclOrch->getAclRule(INGRESS_TABLE_DROP, "mux_acl_rule");
            EXPECT_NE(nullptr, rule);
            return rule;
        }

        vector<sai_object_id_t> SoftwareAclPorts()
        {
            auto rule = SharedRule();
            if (!rule)
                return {};
            auto ports = rule->getInPorts();
            sort(ports.begin(), ports.end());
            return ports;
        }

        vector<sai_object_id_t> HardwareAclPorts()
        {
            auto rule = SharedRule();
            if (!rule)
                return {};
            vector<sai_object_id_t> ports(8);
            sai_attribute_t attr{};
            attr.id = SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS;
            attr.value.aclfield.data.objlist.count = static_cast<uint32_t>(ports.size());
            attr.value.aclfield.data.objlist.list = ports.data();
            auto status = old_sai_acl_api->get_acl_entry_attribute(rule->getOid(), 1, &attr);
            EXPECT_EQ(SAI_STATUS_SUCCESS, status);
            EXPECT_LE(attr.value.aclfield.data.objlist.count, ports.size());
            if (status != SAI_STATUS_SUCCESS || attr.value.aclfield.data.objlist.count > ports.size())
                return {};
            ports.resize(attr.value.aclfield.data.objlist.count);
            sort(ports.begin(), ports.end());
            return ports;
        }

        void MultiMuxRoute(const string& prefix)
        {
            auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            vector<FieldValueTuple> fields{{"nexthop", SERVER_IP1 + ",192.168.1.2"},
                                          {"ifname", VLAN_1000 + "," + VLAN_1000}};
            consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND, fields));
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
            ASSERT_EQ(2u, gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix(prefix)).getSize());
        }

        void FailOneNeighborCreate()
        {
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
                .WillOnce([](CREATE_BULK_PARAMS(neighbor)) -> sai_status_t {
                    EXPECT_EQ(3u, object_count);
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = sai_serialize_ip_address(neighbor_entry[i].ip_address) == "192.168.0.3"
                            ? SAI_STATUS_FAILURE
                            : old_sai_neighbor_api->create_neighbor_entry(&neighbor_entry[i], attr_count[i], attr_list[i]);
                    return SAI_STATUS_FAILURE;
                });
        }
    };

    class MuxTransitionModesTest : public MuxHybridTest, public testing::WithParamInterface<string>
    {
        void ApplyInitialConfigs() override
        {
            m_neighbor_mode = GetParam();
            MuxHybridTest::ApplyInitialConfigs();
        }
    };

    class MuxAssociationTest : public MuxSharedCableTest
    {
    protected:
        const string moving_ip = "192.168.0.3";
        const string moving_mac = "62:f9:65:10:2f:66";
        MuxAssociationTest() { m_server_prefix = SERVER_IP1 + "/32"; }

        void HoldOwnedHop(bool& blocked, int& removals)
        {
            SetFdb(moving_mac, TEST_INTERFACE);
            NeighborEvent(moving_ip, true, moving_mac);
            ASSERT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
            AddRoute("10.40.0.0/24", moving_ip);
            auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
            route_set = [tunnel](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
                if (sai_serialize_ip_prefix(entry->destination) == "10.40.0.0/24" && attr->value.oid != tunnel)
                    return SAI_STATUS_FAILURE;
                return old_sai_route_api->set_route_entry_attribute(entry, attr);
            };
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
                .WillRepeatedly([&, this](sai_object_id_t oid) -> sai_status_t {
                    if (oid == gNeighOrch->getLocalNextHopId(Key(moving_ip)))
                    {
                        ++removals;
                        if (blocked)
                            return SAI_STATUS_FAILURE;
                    }
                    return old_sai_next_hop_api->remove_next_hop(oid);
                });
            SetMuxStateFromAppDb(ACTIVE_STATE);
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
            ASSERT_NE(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
            SetMuxStateFromAppDb(STANDBY_STATE);
            route_set = {};
        }

        void ExerciseTransfer(bool active_on_move, bool move_back, bool activate_later, bool remove_route = false)
        {
            if (active_on_move)
                SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
            bool blocked = true;
            int removals = 0;
            ASSERT_NO_FATAL_FAILURE(HoldOwnedHop(blocked, removals));
            auto oid = gNeighOrch->getLocalNextHopId(Key(moving_ip));
            auto incarnation = gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation;
            SetFdb(moving_mac, "Ethernet8");
            ASSERT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
            if (activate_later)
                SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
            if (move_back)
                SetFdb(moving_mac, TEST_INTERFACE);
            if (remove_route)
                DeleteRoute("10.40.0.0/24");
            bool adopted = active_on_move || activate_later;
            EXPECT_EQ(incarnation, gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation);
            EXPECT_FALSE(incarnation->retired);
            auto crm = CrmUsed();
            int refs = RifRefs();
            int prior_removals = removals;
            blocked = false;
            ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
            EXPECT_EQ(move_back ? TEST_INTERFACE : string("Ethernet8"),
                      m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
            EXPECT_EQ(adopted ? oid : SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
            ExpectNeighborHardware(moving_ip, adopted);
            if (adopted)
            {
                EXPECT_EQ(prior_removals, removals);
                EXPECT_EQ(crm, CrmUsed());
                EXPECT_EQ(refs, RifRefs());
            }
            else
            {
                EXPECT_GT(removals, prior_removals);
                EXPECT_EQ(refs - 2, RifRefs());
            }
            auto target = adopted && !move_back ? oid
                : m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
            EXPECT_EQ(!remove_route && adopted && !move_back ? 1 : 0,
                      gNeighOrch->getNextHopRefCount(Key(moving_ip)));
            if (!remove_route)
            {
                EXPECT_EQ(target, RouteNextHop("10.40.0.0/24"));
                DeleteRoute("10.40.0.0/24");
            }
            EXPECT_EQ(0, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
            NeighborEvent(moving_ip, false);
        }

        void HoldIndependentFailure(bool neighbor_present, bool& blocked, bool retain_route = false)
        {
            SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
            SetFdb(moving_mac, TEST_INTERFACE);
            NeighborEvent(moving_ip, true, moving_mac);
            if (retain_route)
                AddRoute("10.64.0.0/24", moving_ip);
            if (neighbor_present)
            {
                EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
                    .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                        for (uint32_t i = 0; i < object_count; ++i)
                        {
                            object_id[i] = SAI_NULL_OBJECT_ID;
                            object_statuses[i] = SAI_STATUS_TABLE_FULL;
                        }
                        return SAI_STATUS_FAILURE;
                    });
                EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
                    .WillRepeatedly([&, this](const sai_neighbor_entry_t* entry) -> sai_status_t {
                        if (blocked && sai_serialize_ip_address(entry->ip_address) == moving_ip)
                            return SAI_STATUS_FAILURE;
                        return old_sai_neighbor_api->remove_neighbor_entry(entry);
                    });
            }
            else
            {
                EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
                    .WillOnce([this](CREATE_BULK_PARAMS(neighbor)) -> sai_status_t {
                        for (uint32_t i = 0; i < object_count; ++i)
                            object_statuses[i] = sai_serialize_ip_address(neighbor_entry[i].ip_address) == moving_ip
                                ? SAI_STATUS_FAILURE
                                : old_sai_neighbor_api->create_neighbor_entry(&neighbor_entry[i], attr_count[i], attr_list[i]);
                        return SAI_STATUS_FAILURE;
                    });
                EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
                    .WillRepeatedly([&, this](sai_object_id_t oid) -> sai_status_t {
                        if (blocked && oid == gNeighOrch->getLocalNextHopId(Key(moving_ip)))
                            return SAI_STATUS_FAILURE;
                        return old_sai_next_hop_api->remove_next_hop(oid);
                    });
            }
            SetMuxStateFromAppDb(ACTIVE_STATE);
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(neighbor_present, gNeighOrch->isHwConfigured(Key(moving_ip)));
            EXPECT_EQ(!neighbor_present, gNeighOrch->getLocalNextHopId(Key(moving_ip)) != SAI_NULL_OBJECT_ID);
            m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
            SetMuxStateFromAppDb(STANDBY_STATE);
        }
    };

    class MuxConversionTest : public MuxPrefixRecoveryTest,
                              public testing::WithParamInterface<tuple<string, bool>>
    {
    protected:
        MuxConversionTest() { m_second_cable = true; }
    };

    class MuxFgAdmissionTest : public MuxAssociationTest,
                               public testing::WithParamInterface<tuple<bool, bool>> {};

    class MuxNativeReceiverTest : public MuxAssociationTest,
                                  public testing::WithParamInterface<tuple<bool, bool>> {};

    class MuxPrefixMacTest : public MuxPrefixRecoveryTest,
                            public testing::WithParamInterface<bool>
    {
    protected:
        MuxPrefixMacTest() { m_second_cable = true; }
    };

    class MuxVoqSystemTest : public MuxHybridTest, public testing::WithParamInterface<bool>
    {
    protected:
        const string remote = "remote|asic0|Ethernet0";
        const string ip = "192.168.6.3";
        const string mac = "62:f9:65:10:2f:68";
        string previous_switch, previous_inband;
        bool previous_multi = false, configured = false;
        unique_ptr<Table> previous_system, previous_state;

        void PostSetUp() override
        {
            MuxHybridTest::PostSetUp();
            ASSERT_EQ(nullptr, gNeighOrch->getConsumerBase(CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME));
            Port port;
            ASSERT_TRUE(gPortsOrch->getPort(VLAN_1000, port));
            previous_switch = gMySwitchType;
            previous_multi = gMultiAsicVoq;
            previous_inband = gPortsOrch->m_inbandPortName;
            previous_system = std::move(gNeighOrch->m_tableVoqSystemNeighTable);
            previous_state = std::move(gNeighOrch->m_stateSystemNeighTable);
            configured = true;
            port.m_alias = remote;
            port.m_type = Port::SYSTEM;
            port.m_system_port_info.type = SAI_SYSTEM_PORT_TYPE_REMOTE;
            gPortsOrch->setPort(remote, port);
            gPortsOrch->m_inbandPortName = VLAN_1000;
            gIntfsOrch->m_syncdIntfses[remote] = gIntfsOrch->m_syncdIntfses.at(VLAN_1000);
            gIntfsOrch->m_syncdIntfses.at(remote).ref_count = 0;
            gMySwitchType = "voq";
            gMultiAsicVoq = true;
            gNeighOrch->m_tableVoqSystemNeighTable = make_unique<Table>(m_app_db.get(), CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME);
            gNeighOrch->m_stateSystemNeighTable = make_unique<Table>(m_app_db.get(), STATE_SYSTEM_NEIGH_TABLE_NAME);
            gNeighOrch->addExecutor(new Consumer(new SubscriberStateTable(m_app_db.get(),
                CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME, TableConsumable::DEFAULT_POP_BATCH_SIZE, 0),
                gNeighOrch, CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME));
        }

        void PreTearDown() override
        {
            MuxHybridTest::PreTearDown();
            if (!configured)
                return;
            gNeighOrch->m_consumerMap.erase(CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME);
            NeighborContext ctx(NeighborEntry(IpAddress(ip), remote));
            gNeighOrch->removeNeighbor(ctx);
            gPortsOrch->m_portList.erase(remote);
            gIntfsOrch->m_syncdIntfses.erase(remote);
            gPortsOrch->m_inbandPortName = previous_inband;
            gMySwitchType = previous_switch;
            gMultiAsicVoq = previous_multi;
            gNeighOrch->m_tableVoqSystemNeighTable = std::move(previous_system);
            gNeighOrch->m_stateSystemNeighTable = std::move(previous_state);
        }

        string SystemKey() { return remote + gNeighOrch->m_tableVoqSystemNeighTable->getTableNameSeparator() + ip; }

        void SystemEvent(bool add, uint32_t encap = 42)
        {
            auto key = SystemKey();
            vector<FieldValueTuple> fields{{"neigh", mac}, {"encap_index", to_string(encap)}};
            if (add)
                gNeighOrch->m_tableVoqSystemNeighTable->set(key, fields);
            else
                gNeighOrch->m_tableVoqSystemNeighTable->del(key);
            auto consumer = gNeighOrch->getConsumerBase(CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME);
            consumer->addToSync(KeyOpFieldsValuesTuple(key, add ? SET_COMMAND : DEL_COMMAND, fields));
            static_cast<Orch*>(gNeighOrch)->doTask();
        }
    };

    class MuxPreflightTest : public MuxHybridTest,
                             public testing::WithParamInterface<tuple<string, string, string>>
    {
        void ApplyInitialConfigs() override
        {
            m_neighbor_mode = get<0>(GetParam());
            MuxHybridTest::ApplyInitialConfigs();
        }
    };

    TEST_P(MuxPreflightTest, MissingOrdinaryMemberHasNoTransitionSideEffects)
    {
        ThreeNeighbors();
        AddRoute("10.0.0.0/24", SERVER_IP1);
        AddRoute("10.0.1.0/24", "192.168.0.3");
        AddRoute("10.0.2.0/24", "192.168.0.4");
        const auto previous = get<1>(GetParam());
        SetAndAssertMuxState(previous);
        const auto missing = Key(get<2>(GetParam()));
        // Start with real membership and global ownership, then inject only the inconsistency.
        auto saved = gNeighOrch->m_syncdNeighbors.at(missing);
        gNeighOrch->m_syncdNeighbors.erase(missing);
        auto selected = m_MuxCable->nbr_handler_->neighbors_;
        auto ownership = m_MuxOrch->mux_nexthop_tb_;
        auto neighbor_table = gNeighOrch->m_syncdNeighbors;
        auto local = gNeighOrch->m_syncdNextHops;
        auto old_previous = m_MuxCable->prev_state_;
        auto acl = m_MuxCable->acl_handler_.get();
        auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        auto tunnel_count = m_MuxOrch->mux_tunnel_nh_.size();
        auto tunnel_refs = m_MuxOrch->mux_tunnel_nh_.at(m_MuxCable->peer_ip4_).ref_count;
        auto metrics = TableFields(m_MuxCableOrch->mux_metric_table_);
        auto hardware_request = TableFields(*m_MuxCableOrch->mux_table_);
        int refs = RifRefs();
        auto crm = CrmUsed();
        NoProgramming();

        SetMuxStateFromAppDb(previous == ACTIVE_STATE ? STANDBY_STATE : ACTIVE_STATE);
        static_cast<Orch*>(m_MuxCableOrch)->doTask();

        EXPECT_EQ(previous, m_MuxCable->getState());
        EXPECT_EQ(old_previous, m_MuxCable->prev_state_);
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(acl, m_MuxCable->acl_handler_.get());
        EXPECT_EQ(selected, m_MuxCable->nbr_handler_->neighbors_);
        EXPECT_EQ(selected.at(IpAddress(SERVER_IP1)), RouteNextHop("10.0.0.0/24"));
        EXPECT_EQ(selected.at(IpAddress("192.168.0.3")), RouteNextHop("10.0.1.0/24"));
        EXPECT_EQ(selected.at(IpAddress("192.168.0.4")), RouteNextHop("10.0.2.0/24"));
        EXPECT_EQ(ownership, m_MuxOrch->mux_nexthop_tb_);
        EXPECT_EQ(tunnel_count, m_MuxOrch->mux_tunnel_nh_.size());
        EXPECT_EQ(tunnel_refs, m_MuxOrch->mux_tunnel_nh_.at(m_MuxCable->peer_ip4_).ref_count);
        EXPECT_EQ(tunnel, m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_));
        EXPECT_EQ(metrics, TableFields(m_MuxCableOrch->mux_metric_table_));
        EXPECT_EQ(hardware_request, TableFields(*m_MuxCableOrch->mux_table_));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(missing));
        EXPECT_TRUE(m_MuxCable->nbr_handler_->transition_.empty());
        EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
        ASSERT_EQ(neighbor_table.size(), gNeighOrch->m_syncdNeighbors.size());
        for (const auto& neighbor : neighbor_table)
        {
            const auto& now = gNeighOrch->m_syncdNeighbors.at(neighbor.first);
            EXPECT_EQ(neighbor.second.mac, now.mac);
            EXPECT_EQ(neighbor.second.hw_configured, now.hw_configured);
            EXPECT_EQ(neighbor.second.prefix_route, now.prefix_route);
            EXPECT_EQ(neighbor.second.voq_encap_index, now.voq_encap_index);
            EXPECT_EQ(neighbor.second.incarnation, now.incarnation);
            EXPECT_FALSE(now.incarnation->retired);
        }
        ASSERT_EQ(local.size(), gNeighOrch->m_syncdNextHops.size());
        for (const auto& nh : local)
        {
            const auto& now = gNeighOrch->m_syncdNextHops.at(nh.first);
            EXPECT_EQ(nh.second.next_hop_id, now.next_hop_id);
            EXPECT_EQ(nh.second.ref_count, now.ref_count);
            EXPECT_EQ(nh.second.nh_flags, now.nh_flags);
        }
        EXPECT_EQ(1u, m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME)->m_toSync.count(TEST_INTERFACE));
        gNeighOrch->m_syncdNeighbors.emplace(missing, saved);
    }

    INSTANTIATE_TEST_SUITE_P(HostAndPrefixBothDirections, MuxPreflightTest,
        testing::Combine(testing::Values(string("host-route"), string("prefix-route")),
                         testing::Values(ACTIVE_STATE, STANDBY_STATE),
                         testing::Values(string("192.168.0.2"), string("192.168.0.3"), string("192.168.0.4"))));

    TEST_F(MuxHybridTest, DeferredRequestSucceedsAfterNormalNeighborNotification)
    {
        ThreeNeighbors();
        gNeighOrch->m_syncdNeighbors.erase(Key("192.168.0.3"));
        auto acl = m_MuxCable->acl_handler_.get();
        SetMuxStateFromAppDb(ACTIVE_STATE);
        auto pending = m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME);
        ASSERT_EQ(1u, pending->m_toSync.count(TEST_INTERFACE));
        EXPECT_EQ(acl, m_MuxCable->acl_handler_.get());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());

        NeighborEvent("192.168.0.3");
        static_cast<Orch*>(m_MuxCableOrch)->doTask();
        EXPECT_EQ(0u, pending->m_toSync.count(TEST_INTERFACE));
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_NE(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key("192.168.0.3")));
        ExpectNeighborHardware("192.168.0.3", true);
    }

    TEST_P(MuxTransitionModesTest, AuthoritativeDeleteCleansOwnershipAndAllowsReadd)
    {
        ThreeNeighbors();
        NeighborEvent("192.168.0.3", false);
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(Key("192.168.0.3")));
        EXPECT_EQ(0u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress("192.168.0.3")));
        EXPECT_EQ(0u, m_MuxOrch->mux_nexthop_tb_.count(Key("192.168.0.3")));
        SetAndAssertMuxState(ACTIVE_STATE);
        NeighborEvent("192.168.0.3");
        EXPECT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key("192.168.0.3")));
        EXPECT_EQ(1u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress("192.168.0.3")));
        ExpectNeighborHardware("192.168.0.3", true);
    }

    TEST_P(MuxTransitionModesTest, EmptyAndUnresolvedMembershipDoNotPreventActive)
    {
        NeighborEvent(SERVER_IP1, false);
        ASSERT_TRUE(m_MuxCable->nbr_handler_->neighbors_.empty());
        SetAndAssertMuxState(ACTIVE_STATE);
        SetAndAssertMuxState(STANDBY_STATE);
        NeighborEvent("192.168.0.9", true, "00:00:00:00:00:00");
        ASSERT_TRUE(m_MuxCable->nbr_handler_->neighbors_.empty());
        ASSERT_TRUE(m_MuxOrch->isStandaloneTunnelRouteInstalled(IpAddress("192.168.0.9")));
        SetAndAssertMuxState(ACTIVE_STATE);
        EXPECT_TRUE(m_MuxOrch->isStandaloneTunnelRouteInstalled(IpAddress("192.168.0.9")));
        ExpectNeighborHardware("192.168.0.9", false);
        NeighborEvent("192.168.0.9");
        EXPECT_FALSE(m_MuxOrch->isStandaloneTunnelRouteInstalled(IpAddress("192.168.0.9")));
        EXPECT_EQ(1u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress("192.168.0.9")));
        ExpectNeighborHardware("192.168.0.9", true);
    }

    class MuxBfdDetachTest : public MuxHybridTest, public testing::WithParamInterface<bool> {};

    TEST_P(MuxBfdDetachTest, PartialDetachPreservesMembershipAndRetriesAcknowledgedBindings)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, SERVER_IP1));
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, SERVER_IP1, "VrfBfd"));
        auto old = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        auto crm = CrmUsed();
        auto refs = RifRefs();
        bool blocked = true;
        bfd_set = [&](sai_object_id_t oid, const sai_attribute_t* attr) -> sai_status_t {
            if (blocked && ((oid == bfd.Id(1) && attr->value.oid == SAI_NULL_OBJECT_ID) ||
                (GetParam() && oid == bfd.Id(0) && attr->value.oid == old)))
                return SAI_STATUS_FAILURE;
            return old_sai_bfd_api->set_bfd_session_attribute(oid, attr);
        };
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).Times(0);
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        const auto key = VLAN_1000 + ":" + SERVER_IP1;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, {}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(1u, consumer->m_toSync.count(key));
        EXPECT_FALSE(incarnation->retired);
        EXPECT_EQ(1u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress(SERVER_IP1)));
        EXPECT_EQ(old, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(refs, RifRefs());
        bfd.ExpectBinding(0, GetParam() ? SAI_NULL_OBJECT_ID : old);
        bfd.ExpectBinding(1, old);

        testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_api);
        blocked = false;
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .WillOnce([&](sai_object_id_t oid) -> sai_status_t {
                bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
                bfd.ExpectBinding(1, SAI_NULL_OBJECT_ID);
                return old_sai_next_hop_api->remove_next_hop(oid);
            });
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_TRUE(incarnation->retired);
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(Key(SERVER_IP1)));
        EXPECT_EQ(0u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress(SERVER_IP1)));
        ExpectRemovedNextHop(old);
    }

    INSTANTIATE_TEST_SUITE_P(RestoreOutcome, MuxBfdDetachTest, testing::Bool());

    TEST_F(MuxHybridTest, IdenticalSetCannotCancelDeleteUntilBfdRebindSucceeds)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, SERVER_IP1));
        const auto old = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        const auto data = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1));
        const auto refs = RifRefs();
        const auto crm = CrmUsed();
        bool blocked = true;
        bfd_set = [&](sai_object_id_t oid, const sai_attribute_t* attr) -> sai_status_t {
            return blocked && attr->value.oid == old ? SAI_STATUS_FAILURE
                : old_sai_bfd_api->set_bfd_session_attribute(oid, attr);
        };
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).WillRepeatedly(Return(SAI_STATUS_FAILURE));
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        const auto key = VLAN_1000 + ":" + SERVER_IP1;
        const vector<FieldValueTuple> fields{{"neigh", data.mac.to_string()}, {"family", "IPv4"}};
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, {}));
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND, fields));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(2u, consumer->m_toSync.count(key));
        auto entry = consumer->m_toSync.equal_range(key).first;
        EXPECT_EQ(DEL_COMMAND, kfvOp(entry->second));
        ++entry;
        EXPECT_EQ(SET_COMMAND, kfvOp(entry->second));
        EXPECT_EQ(fields, kfvFieldsValues(entry->second));
        EXPECT_FALSE(data.incarnation->retired);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);

        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        bfd.ExpectBinding(0, old);
        EXPECT_EQ(old, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_F(MuxHybridTest, PartialDeleteBindsOnlyTheReplacementNextHop)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, SERVER_IP1));
        const auto old = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        const auto data = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1));
        const auto refs = RifRefs();
        const auto crm = CrmUsed();
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).WillRepeatedly(Return(SAI_STATUS_FAILURE));
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        const auto key = VLAN_1000 + ":" + SERVER_IP1;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, {}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_TRUE(gNeighOrch->isHwConfigured(Key(SERVER_IP1)));
        EXPECT_FALSE(data.incarnation->retired);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        ExpectRemovedNextHop(old);
        bfd_set = [&](sai_object_id_t oid, const sai_attribute_t* attr) -> sai_status_t {
            EXPECT_NE(old, attr->value.oid);
            return old_sai_bfd_api->set_bfd_session_attribute(oid, attr);
        };
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
            .WillOnce([](GENERIC_CREATE_PARAMS(next_hop)) -> sai_status_t {
                return old_sai_next_hop_api->create_next_hop(GENERIC_CREATE_ARGS(next_hop));
            });
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND,
            vector<FieldValueTuple>{{"neigh", data.mac.to_string()}, {"family", "IPv4"}}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        const auto replacement = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, replacement);
        EXPECT_NE(old, replacement);
        bfd.ExpectBinding(0, replacement);
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_F(MuxHybridTest, BfdCreationKeepsLegitimateStandbyBindingNull)
    {
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, SERVER_IP1));
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        NeighborEvent(SERVER_IP1);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getReadyLocalNextHopId(Key(SERVER_IP1)));
    }

    TEST_F(MuxHybridTest, MixedRouteRetainsReadyLabeledNonMuxBackup)
    {
        ASSERT_EQ(STANDBY_STATE, m_MuxCable->getState());
        const string backup = "192.168.6.4";
        const string prefix = "10.65.0.0/24";
        const auto initial_rif_refs = RifRefs();
        NeighborEvent(backup, true, "62:f9:65:10:2f:77");
        ASSERT_TRUE(m_MuxOrch->getNexthopMuxName(Key(backup)).empty());
        ASSERT_TRUE(gNeighOrch->isHwConfigured(Key(backup)));

        auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
        vector<FieldValueTuple> fields{{"nexthop", SERVER_IP1 + "," + backup},
                                       {"ifname", VLAN_1000 + "," + VLAN_1000},
                                       {"mpls_nh", "na,push100"}};
        consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND, fields));
        static_cast<Orch*>(gRouteOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        ASSERT_EQ(2u, gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix(prefix)).getSize());

        const NextHopKey labeled("push100+" + backup, VLAN_1000);
        const auto labeled_oid = gNeighOrch->getLocalNextHopId(labeled);
        ASSERT_NE(SAI_NULL_OBJECT_ID, labeled_oid);
        ASSERT_NE(gNeighOrch->getLocalNextHopId(Key(backup)), labeled_oid);
        EXPECT_FALSE(gNeighOrch->isHwConfigured(labeled));
        sai_attribute_t attr{};
        attr.id = SAI_NEXT_HOP_ATTR_TYPE;
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_next_hop_api->get_next_hop_attribute(labeled_oid, 1, &attr));
        EXPECT_EQ(SAI_NEXT_HOP_TYPE_MPLS, attr.value.s32);

        const auto nh_refs = gNeighOrch->getNextHopRefCount(labeled);
        const auto rif_refs = RifRefs();
        for (int retry = 0; retry < 2; ++retry)
        {
            m_MuxCable->updateNeighbor(Key(SERVER_IP1), true);
            EXPECT_EQ(labeled_oid, RouteNextHop(prefix));
            EXPECT_EQ(nh_refs, gNeighOrch->getNextHopRefCount(labeled));
            EXPECT_EQ(rif_refs, RifRefs());
        }

        consumer->addToSync(KeyOpFieldsValuesTuple(prefix, DEL_COMMAND, {}));
        static_cast<Orch*>(gRouteOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(labeled));
        NeighborEvent(backup, false);
        EXPECT_EQ(initial_rif_refs, RifRefs());
    }

    TEST_F(MuxHybridTest, AlreadyStandbyWithoutLocalNextHopIsANoop)
    {
        ThreeNeighbors();
        auto selected = m_MuxCable->nbr_handler_->neighbors_;
        NoProgramming();
        ASSERT_TRUE(m_MuxCable->nbr_handler_->prepareStateChange());
        EXPECT_TRUE(m_MuxCable->nbr_handler_->disable(selected.begin()->second));
        EXPECT_TRUE(m_MuxCable->nbr_handler_->rollback(false, selected.begin()->second, false));
        EXPECT_TRUE(m_MuxCable->nbr_handler_->cleanupRollback());
        EXPECT_EQ(selected, m_MuxCable->nbr_handler_->neighbors_);
        m_MuxCable->nbr_handler_->commitStateChange();
    }

    TEST_F(MuxHybridTest, UnresolvedOrdinaryEntryIsDeferredWithoutPruning)
    {
        auto& member = gNeighOrch->m_syncdNeighbors.at(Key(SERVER_IP1));
        auto mac = member.mac;
        member.mac = MacAddress();
        NoProgramming();
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(1u, m_MuxCable->nbr_handler_->neighbors_.count(IpAddress(SERVER_IP1)));
        EXPECT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(SERVER_IP1)));
        member.mac = mac;
    }

    TEST_F(MuxHybridTest, PreparationFailureDoesNotLeakObjectsOrLoseAcl)
    {
        ThreeNeighbors();
        Port vlan;
        ASSERT_TRUE(gPortsOrch->getPort(VLAN_1000, vlan));
        auto unavailable = vlan;
        unavailable.m_vlan_info.vlan_oid = SAI_NULL_OBJECT_ID;
        gPortsOrch->setPort(VLAN_1000, unavailable);
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        gPortsOrch->setPort(VLAN_1000, vlan);
        ExpectStandbyRestored(refs);
    }

    TEST_F(MuxHybridTest, MixedNeighborResultsCleanIndependentlyCreatedNextHops)
    {
        ThreeNeighbors();
        int refs = RifRefs();
        auto crm = CrmUsed();
        vector<sai_object_id_t> created;
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
            .WillOnce([](CREATE_BULK_PARAMS(neighbor)) -> sai_status_t {
                EXPECT_EQ(3u, object_count);
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    auto ip = sai_serialize_ip_address(neighbor_entry[i].ip_address);
                    object_statuses[i] = ip == SERVER_IP1
                        ? old_sai_neighbor_api->create_neighbor_entry(&neighbor_entry[i], attr_count[i], attr_list[i])
                        : ip == "192.168.0.3" ? SAI_STATUS_TABLE_FULL : SAI_STATUS_NOT_EXECUTED;
                }
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                EXPECT_EQ(3u, object_count);
                auto status = old_sai_next_hop_api->create_next_hops(GENERIC_BULK_CREATE_ARGS(next_hop));
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    EXPECT_EQ(SAI_STATUS_SUCCESS, object_statuses[i]);
                    created.push_back(object_id[i]);
                }
                return status;
            });
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).Times(3);
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).Times(1);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ExpectStandbyRestored(refs);
        EXPECT_EQ(crm, CrmUsed());
        for (auto oid : created)
            ExpectRemovedNextHop(oid);
    }

    TEST_F(MuxHybridTest, NextHopStatusesRemainDistinctForNullObjectIds)
    {
        ThreeNeighbors();
        int refs = RifRefs();
        map<string, sai_status_t> expected;
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                EXPECT_EQ(3u, object_count);
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    object_id[i] = SAI_NULL_OBJECT_ID;
                    object_statuses[i] = i == 0
                        ? old_sai_next_hop_api->create_next_hop(&object_id[i], switch_id, attr_count[i], attr_list[i])
                        : i == 1 ? SAI_STATUS_TABLE_FULL : SAI_STATUS_NOT_EXECUTED;
                    for (uint32_t j = 0; j < attr_count[i]; ++j)
                        if (attr_list[i][j].id == SAI_NEXT_HOP_ATTR_IP)
                            expected[sai_serialize_ip_address(attr_list[i][j].value.ipaddr)] = object_statuses[i];
                }
                return SAI_STATUS_FAILURE;
            });
        EXPECT_THROW(m_MuxCable->setState(ACTIVE_STATE), runtime_error);
        ASSERT_EQ(3u, expected.size());
        for (const auto& ctx : m_MuxCable->nbr_handler_->neighbor_contexts_)
        {
            EXPECT_EQ(expected.at(ctx.neighborEntry.ip_address.to_string()), ctx.nexthop_status);
        }
        m_MuxCable->rollbackStateChange();
        ExpectStandbyRestored(refs);
    }

    TEST_F(MuxHybridTest, BulkFailureWithoutObjectResultsDoesNotInventSuccess)
    {
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
            .WillOnce(Return(SAI_STATUS_FAILURE));
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).Times(1);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ExpectStandbyRestored(refs);
    }

    TEST_F(MuxHybridTest, ExistingNeighborWithFailedNextHopIsNotOwnedByRollback)
    {
        auto entry = SaiNeighbor(SERVER_IP1);
        sai_attribute_t attr{};
        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        memcpy(attr.value.mac, MacAddress(MAC4).getMac(), sizeof(sai_mac_t));
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_neighbor_api->create_neighbor_entry(&entry, 1, &attr));
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                EXPECT_EQ(1u, object_count);
                object_id[0] = SAI_NULL_OBJECT_ID;
                object_statuses[0] = SAI_STATUS_TABLE_FULL;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries).Times(0);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_TRUE(gNeighOrch->isHwConfigured(Key(SERVER_IP1)));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(refs + 1, RifRefs()); // Existing hardware is now explicitly accounted for.
        ExpectNeighborHardware(SERVER_IP1, true);
    }

    TEST_F(MuxHybridTest, RemovedNextHopIsRecreatedWhenNeighborRemovalFails)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.0.0.0/24", SERVER_IP1);
        auto old_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        int refs = RifRefs();
        int nh_refs = gNeighOrch->getNextHopRefCount(Key(SERVER_IP1));
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                EXPECT_EQ(1u, object_count);
                object_statuses[0] = SAI_STATUS_FAILURE;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries).Times(0);
        SetMuxStateFromAppDb(STANDBY_STATE);
        auto restored_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        ASSERT_NE(SAI_NULL_OBJECT_ID, restored_oid);
        EXPECT_NE(old_oid, restored_oid);
        EXPECT_EQ(restored_oid, m_MuxCable->nbr_handler_->neighbors_.at(IpAddress(SERVER_IP1)));
        EXPECT_EQ(restored_oid, RouteNextHop("10.0.0.0/24"));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(nh_refs, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        ExpectRemovedNextHop(old_oid);
        ExpectNeighborHardware(SERVER_IP1, true);
    }

    TEST_F(MuxHybridTest, FailedNeighborRecoveryStillRestoresAclAndReportsFailure)
    {
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                object_id[0] = SAI_NULL_OBJECT_ID;
                object_statuses[0] = SAI_STATUS_TABLE_FULL;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
            .WillOnce(Return(SAI_STATUS_FAILURE));
        EXPECT_CALL(*mock_sai_acl_api, create_acl_entry).Times(1);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_NE(nullptr, m_MuxCable->acl_handler_);
        ExpectNeighborHardware(SERVER_IP1, true);
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(1u, PendingMuxRequest());
        auto feedback = m_MuxStateOrch->getConsumerBase(STATE_HW_MUX_CABLE_TABLE_NAME);
        feedback->addToSync(KeyOpFieldsValuesTuple(
            TEST_INTERFACE, SET_COMMAND, vector<FieldValueTuple>{{STATE, STANDBY_STATE}}));
        static_cast<Orch*>(m_MuxStateOrch)->doTask();
        string reported;
        ASSERT_TRUE(m_MuxStateOrch->mux_state_table_.hget(TEST_INTERFACE, STATE, reported));
        EXPECT_EQ("error", reported);

        // The retained same-state request drives recovery only when its backoff expires.
        testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        ExpectNeighborHardware(SERVER_IP1, false);
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
        EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
    }

    TEST_F(MuxHybridTest, RemovedNeighborRetainsItsNextHopWhenNextHopRemovalFails)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        auto old_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
            .WillOnce([](GENERIC_BULK_REMOVE_PARAMS(next_hop)) -> sai_status_t {
                EXPECT_EQ(1u, object_count);
                object_statuses[0] = SAI_STATUS_FAILURE;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(old_oid, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        ExpectNeighborHardware(SERVER_IP1, true);
    }

    TEST_F(MuxHybridTest, AclRecoveryFailureCannotBeReportedAsSuccess)
    {
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                object_id[0] = SAI_NULL_OBJECT_ID;
                object_statuses[0] = SAI_STATUS_TABLE_FULL;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_acl_api, create_acl_entry).WillOnce(Return(SAI_STATUS_FAILURE));
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(nullptr, m_MuxCable->acl_handler_);
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        testing::Mock::VerifyAndClearExpectations(mock_sai_acl_api);
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_NE(nullptr, m_MuxCable->acl_handler_);
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
    }

    TEST_F(MuxHybridTest, ExistingHostRouteIsNotDeletedByFailedTransition)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        auto route = SaiRoute(SERVER_IP1);
        sai_attribute_t attr{};
        attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        attr.value.oid = tunnel;
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_route_api->create_route_entry(&route, 1, &attr));
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                object_statuses[0] = SAI_STATUS_FAILURE;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_route_api, remove_route_entries).Times(0);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(tunnel, RouteNextHop(SERVER_IP1));
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_route_api->remove_route_entry(&route));
    }

    TEST_F(MuxHybridTest, MixedRemoveResultsRestoreEverySubmittedMember)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.0.0.0/24", SERVER_IP1);
        AddRoute("10.0.1.0/24", "192.168.0.3");
        AddRoute("10.0.2.0/24", "192.168.0.4");
        auto before = gNeighOrch->m_syncdNextHops;
        int refs = RifRefs();
        auto crm = CrmUsed();
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                EXPECT_EQ(3u, object_count);
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    auto ip = sai_serialize_ip_address(neighbor_entry[i].ip_address);
                    object_statuses[i] = ip == SERVER_IP1
                        ? old_sai_neighbor_api->remove_neighbor_entry(&neighbor_entry[i])
                        : ip == "192.168.0.3" ? SAI_STATUS_FAILURE : SAI_STATUS_NOT_EXECUTED;
                }
                return SAI_STATUS_FAILURE;
            });
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(nullptr, m_MuxCable->acl_handler_);
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        for (const auto& old : before)
        {
            auto ip = old.first.ip_address.to_string();
            auto oid = gNeighOrch->getLocalNextHopId(old.first);
            ASSERT_NE(SAI_NULL_OBJECT_ID, oid);
            EXPECT_NE(old.second.next_hop_id, oid);
            EXPECT_EQ(oid, m_MuxCable->nbr_handler_->neighbors_.at(old.first.ip_address));
            EXPECT_EQ(old.second.ref_count, gNeighOrch->getNextHopRefCount(old.first));
            EXPECT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(old.first));
            ExpectRemovedNextHop(old.second.next_hop_id);
            ExpectNeighborHardware(ip, true);
        }
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)), RouteNextHop("10.0.0.0/24"));
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key("192.168.0.3")), RouteNextHop("10.0.1.0/24"));
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key("192.168.0.4")), RouteNextHop("10.0.2.0/24"));
    }

    TEST_F(MuxHybridTest, MixedNextHopRemoveResultsDoNotRecreateUntouchedObjects)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        auto before = gNeighOrch->m_syncdNextHops;
        auto crm = CrmUsed();
        int refs = RifRefs();
        map<sai_object_id_t, sai_status_t> outcomes;
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
            .WillOnce([&](GENERIC_BULK_REMOVE_PARAMS(next_hop)) -> sai_status_t {
                EXPECT_EQ(3u, object_count);
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    object_statuses[i] = i == 0 ? old_sai_next_hop_api->remove_next_hop(object_id[i])
                                             : i == 1 ? SAI_STATUS_FAILURE : SAI_STATUS_NOT_EXECUTED;
                    outcomes[object_id[i]] = object_statuses[i];
                }
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        ASSERT_EQ(3u, outcomes.size());
        for (const auto& old : before)
        {
            auto oid = gNeighOrch->getLocalNextHopId(old.first);
            if (outcomes.at(old.second.next_hop_id) == SAI_STATUS_SUCCESS)
            {
                EXPECT_NE(old.second.next_hop_id, oid);
                ExpectRemovedNextHop(old.second.next_hop_id);
            }
            else
            {
                EXPECT_EQ(old.second.next_hop_id, oid);
            }
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_ATTR_TYPE;
            EXPECT_EQ(SAI_STATUS_SUCCESS, old_sai_next_hop_api->get_next_hop_attribute(oid, 1, &attr));
            EXPECT_EQ(old.second.ref_count, gNeighOrch->getNextHopRefCount(old.first));
            ExpectNeighborHardware(old.first.ip_address.to_string(), true);
        }
    }

    TEST_P(MuxTransitionModesTest, PartialRouteFailureDoesNotReplayUntouchedNeighbor)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.0.0.0/24", SERVER_IP1);
        AddRoute("10.0.1.0/25", "192.168.0.3");
        AddRoute("10.0.1.128/25", "192.168.0.3");
        AddRoute("10.0.2.0/24", "192.168.0.4");
        auto before = gNeighOrch->m_syncdNextHops;
        int rif_refs = RifRefs();
        int failure = 0;
        int untouched_updates = 0;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            auto prefix = sai_serialize_ip_prefix(entry->destination);
            if (prefix == "10.0.2.0/24")
                ++untouched_updates;
            if (prefix == "10.0.1.128/25" && failure++ == 0)
                return SAI_STATUS_INSUFFICIENT_RESOURCES;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops).Times(0);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(0, untouched_updates);
        EXPECT_EQ(rif_refs, RifRefs());
        for (const auto& old : before)
        {
            EXPECT_EQ(old.second.next_hop_id, gNeighOrch->getLocalNextHopId(old.first));
            EXPECT_EQ(old.second.ref_count, gNeighOrch->getNextHopRefCount(old.first));
            EXPECT_EQ(old.second.next_hop_id, m_MuxCable->nbr_handler_->neighbors_.at(old.first.ip_address));
        }
        EXPECT_EQ(before.at(Key(SERVER_IP1)).next_hop_id, RouteNextHop("10.0.0.0/24"));
        EXPECT_EQ(before.at(Key("192.168.0.3")).next_hop_id, RouteNextHop("10.0.1.0/25"));
        EXPECT_EQ(before.at(Key("192.168.0.3")).next_hop_id, RouteNextHop("10.0.1.128/25"));
        EXPECT_EQ(before.at(Key("192.168.0.4")).next_hop_id, RouteNextHop("10.0.2.0/24"));
        if (GetParam() == "prefix-route")
        {
            for (const auto& old : before)
            {
                EXPECT_EQ(old.second.next_hop_id, RouteNextHop(old.first.ip_address.to_string()));
            }
        }
    }

    TEST_P(MuxTransitionModesTest, PartialRecoveryTracksReferencesUntilExplicitRetry)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.0.0.0/25", SERVER_IP1);
        AddRoute("10.0.0.128/25", SERVER_IP1);
        AddRoute("10.0.1.0/24", "192.168.0.3");
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        int original_refs = gNeighOrch->getNextHopRefCount(Key(SERVER_IP1));
        bool forward_failed = false;
        bool recovery_failed = false;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            auto prefix = sai_serialize_ip_prefix(entry->destination);
            if (prefix == "10.0.1.0/24" && !forward_failed)
            {
                forward_failed = true;
                return SAI_STATUS_FAILURE;
            }
            if (prefix == "10.0.0.128/25" && forward_failed && !recovery_failed)
            {
                recovery_failed = true;
                return SAI_STATUS_FAILURE;
            }
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_TRUE(forward_failed);
        EXPECT_TRUE(recovery_failed);
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(local, RouteNextHop("10.0.0.0/25"));
        EXPECT_NE(local, RouteNextHop("10.0.0.128/25"));
        EXPECT_EQ(original_refs - 1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));

        m_MuxCable->rollbackStateChange();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(local, RouteNextHop("10.0.0.128/25"));
        EXPECT_EQ(original_refs, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
    }

    TEST_P(MuxTransitionModesTest, MissingPrefixLocalNextHopIsNotTreatedAsStandalone)
    {
        if (GetParam() == "host-route")
        {
            // This is the normal standby case for host-route mode.
            ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
            ASSERT_TRUE(m_MuxCable->nbr_handler_->prepareStateChange(false));
            m_MuxCable->nbr_handler_->commitStateChange();
        }
        else
        {
            auto nh = gNeighOrch->m_syncdNextHops.at(Key(SERVER_IP1));
            gNeighOrch->m_syncdNextHops.erase(Key(SERVER_IP1));
            NoProgramming();
            SetMuxStateFromAppDb(ACTIVE_STATE);
            EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
            EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(1u, m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME)->m_toSync.count(TEST_INTERFACE));
            gNeighOrch->m_syncdNextHops.emplace(Key(SERVER_IP1), nh);
        }
    }

    TEST_F(MuxHybridTest, RestoreRetainsCreatedNextHopAcrossPartialFgRebindFailure)
    {
        const string prefix = "10.83.0.0/24";
        const string backup = "192.168.5.2";
        SetAndAssertMuxState(ACTIVE_STATE);
        NeighborEvent(backup);
        ConfigureFg(prefix);
        auto members = gFgNhgOrch->getConsumerBase(CFG_FG_NHG_MEMBER);
        members->addToSync(KeyOpFieldsValuesTuple(backup, SET_COMMAND,
            vector<FieldValueTuple>{{"FG_NHG", "mux-recovery-fg"}, {"bank", "0"}}));
        static_cast<Orch*>(gFgNhgOrch)->doTask();
        ASSERT_TRUE(members->m_toSync.empty());
        auto routes = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
        routes->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND,
            vector<FieldValueTuple>{{"nexthop", SERVER_IP1 + "," + backup},
                                   {"ifname", VLAN_1000 + "," + VLAN_1000}}));
        static_cast<Orch*>(gRouteOrch)->doTask();
        ASSERT_EQ(0u, routes->m_toSync.count(prefix));
        const auto old_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        const auto backup_oid = gNeighOrch->getLocalNextHopId(Key(backup));
        const auto baseline = CrmUsed();
        const auto refs = RifRefs();
        bool blocked = true;
        int rebinds = 0;
        group_member_set = [&](sai_object_id_t oid, const sai_attribute_t* attr) -> sai_status_t {
            if (attr->id == SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID && attr->value.oid != backup_oid)
            {
                ++rebinds;
                if (blocked && rebinds > 1)
                    return SAI_STATUS_FAILURE;
            }
            return old_sai_next_hop_group_api->set_next_hop_group_member_attribute(oid, attr);
        };
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                for (uint32_t i = 0; i < object_count; ++i)
                    object_statuses[i] = SAI_STATUS_FAILURE;
                return SAI_STATUS_FAILURE;
            });
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops)
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) -> sai_status_t {
                return old_sai_next_hop_api->create_next_hops(GENERIC_BULK_CREATE_ARGS(next_hop));
            });
        SetMuxStateFromAppDb(STANDBY_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        ASSERT_GT(rebinds, 1);
        const auto restored_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, restored_oid);
        ASSERT_NE(old_oid, restored_oid);
        ASSERT_EQ(1u, m_MuxCable->nbr_handler_->neighbor_contexts_.size());
        const auto& progress = m_MuxCable->nbr_handler_->neighbor_contexts_.front();
        EXPECT_TRUE(progress.nexthop_created);
        EXPECT_EQ(restored_oid, progress.next_hop_id);
        const auto partial = CrmUsed();
        for (const auto& counter : baseline)
        {
            if (counter.first.first == static_cast<int>(CrmResourceType::CRM_IPV4_NEXTHOP) ||
                counter.first.first == static_cast<int>(CrmResourceType::CRM_IPV4_NEIGHBOR))
            {
                EXPECT_EQ(counter.second, partial.at(counter.first));
            }
        }
        const auto& partial_fg = gFgNhgOrch->m_syncdFGRouteTables.at(gVirtualRouterId).at(IpPrefix(prefix));
        size_t partially_bound = 0;
        for (auto member : partial_fg.nhopgroup_members)
        {
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            ASSERT_EQ(SAI_STATUS_SUCCESS,
                old_sai_next_hop_group_api->get_next_hop_group_member_attribute(member, 1, &attr));
            partially_bound += attr.value.oid == restored_oid;
        }
        EXPECT_GT(partially_bound, 0u);
        EXPECT_LT(partially_bound, partial_fg.nhopgroup_members.size());
        EXPECT_EQ(refs, RifRefs());
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(restored_oid, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(backup)));
        const auto& fg = gFgNhgOrch->m_syncdFGRouteTables.at(gVirtualRouterId).at(IpPrefix(prefix));
        EXPECT_EQ(2u, fg.active_nexthops.size());
        size_t restored_buckets = 0, backup_buckets = 0;
        for (auto member : fg.nhopgroup_members)
        {
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            ASSERT_EQ(SAI_STATUS_SUCCESS,
                old_sai_next_hop_group_api->get_next_hop_group_member_attribute(member, 1, &attr));
            EXPECT_TRUE(attr.value.oid == restored_oid || attr.value.oid == backup_oid);
            restored_buckets += attr.value.oid == restored_oid;
            backup_buckets += attr.value.oid == backup_oid;
        }
        EXPECT_GT(restored_buckets, 0u);
        EXPECT_GT(backup_buckets, 0u);
        EXPECT_EQ(baseline, CrmUsed());
        EXPECT_EQ(refs, RifRefs());
        ExpectRemovedNextHop(old_oid);
        DeleteRoute(prefix);
    }

    class MuxGroupDeleteTest : public MuxHybridTest, public testing::WithParamInterface<bool> {};

    TEST_P(MuxGroupDeleteTest, GroupDeleteRetryPreservesReleasedReferencesAndRemainingMembers)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        const auto baseline = CrmUsed();
        AddRoute("10.80.0.0/24", SERVER_IP1);
        AddEcmpRoute("10.81.0.0/24");
        const auto group = gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix("10.81.0.0/24"));
        bool recovery_blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.80.0.0/24", recovery_blocked, restores));
        ASSERT_NE(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        ASSERT_TRUE(gRouteOrch->m_syncdNextHopGroups.at(group).nhopgroup_members.at(Key(SERVER_IP1)).mux_ref_released);
        AddRoute("10.82.0.0/24", SERVER_IP1);
        ASSERT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        bool blocked = true;
        map<sai_object_id_t, int> removed_members;
        group_members_remove = [&](GENERIC_BULK_REMOVE_PARAMS(next_hop_group_member)) -> sai_status_t {
            bool success = true;
            for (uint32_t i = 0; i < object_count; ++i)
            {
                object_statuses[i] = blocked && GetParam() && i == 0 ? SAI_STATUS_FAILURE
                    : old_sai_next_hop_group_api->remove_next_hop_group_member(object_id[i]);
                if (object_statuses[i] == SAI_STATUS_SUCCESS)
                    ++removed_members[object_id[i]];
                else
                    success = false;
            }
            return success ? SAI_STATUS_SUCCESS : SAI_STATUS_FAILURE;
        };
        group_remove = [&](sai_object_id_t oid) -> sai_status_t {
            return blocked && !GetParam() ? SAI_STATUS_FAILURE
                : old_sai_next_hop_group_api->remove_next_hop_group(oid);
        };
        DeleteRoute("10.81.0.0/24");
        ASSERT_EQ(1u, gRouteOrch->m_syncdNextHopGroups.count(group));
        EXPECT_EQ(1u, gRouteOrch->m_syncdNextHopGroups.at(group).mux_released_members.count(Key(SERVER_IP1)));
        EXPECT_EQ(GetParam() ? 1u : 0u, gRouteOrch->m_syncdNextHopGroups.at(group).nhopgroup_members.size());
        blocked = false;
        ASSERT_TRUE(gRouteOrch->removeNextHopGroup(group));
        EXPECT_EQ(0u, gRouteOrch->m_syncdNextHopGroups.count(group));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        for (const auto& removed : removed_members)
        {
            EXPECT_EQ(1, removed.second);
        }
        recovery_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        DeleteRoute("10.80.0.0/24");
        DeleteRoute("10.82.0.0/24");
        EXPECT_EQ(baseline, CrmUsed());
    }

    INSTANTIATE_TEST_SUITE_P(RemovalPhase, MuxGroupDeleteTest, testing::Bool());

    TEST_P(MuxTransitionModesTest, PartialEcmpFailureRestoresMembersWithoutRefcountInflation)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        NextHopGroupKey group("192.168.0.2@Vlan1000,192.168.0.3@Vlan1000,192.168.0.4@Vlan1000");
        ASSERT_TRUE(gRouteOrch->addNextHopGroup(group));
        const auto old_group = gRouteOrch->m_syncdNextHopGroups.at(group);
        ASSERT_EQ(3u, old_group.nh_member_install_count);
        auto before = gNeighOrch->m_syncdNextHops;
        auto fail_member = old_group.nhopgroup_members.at(Key("192.168.0.3")).next_hop_id;
        auto untouched_member = old_group.nhopgroup_members.at(Key("192.168.0.4")).next_hop_id;
        bool failed = false;
        EXPECT_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member)
            .WillRepeatedly([&](sai_object_id_t oid) -> sai_status_t {
                EXPECT_NE(untouched_member, oid);
                if (oid == fail_member && !failed)
                {
                    failed = true;
                    return SAI_STATUS_FAILURE;
                }
                return old_sai_next_hop_group_api->remove_next_hop_group_member(oid);
            });
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_TRUE(failed);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        const auto& restored = gRouteOrch->m_syncdNextHopGroups.at(group);
        EXPECT_EQ(old_group.nh_member_install_count, restored.nh_member_install_count);
        EXPECT_EQ(untouched_member, restored.nhopgroup_members.at(Key("192.168.0.4")).next_hop_id);
        for (const auto& old : before)
        {
            EXPECT_EQ(old.second.ref_count, gNeighOrch->getNextHopRefCount(old.first));
            auto member = restored.nhopgroup_members.at(old.first).next_hop_id;
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            ASSERT_EQ(SAI_STATUS_SUCCESS,
                      old_sai_next_hop_group_api->get_next_hop_group_member_attribute(member, 1, &attr));
            EXPECT_EQ(old.second.next_hop_id, attr.value.oid);
        }
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_group_api);
        ASSERT_TRUE(gRouteOrch->removeNextHopGroup(group));
    }

    TEST_P(MuxTransitionModesTest, PrefixOrHostRouteFailureCompensatesAllChangedEntries)
    {
        ThreeNeighbors();
        auto selected = m_MuxCable->nbr_handler_->neighbors_;
        int refs = RifRefs();
        if (GetParam() == "prefix-route")
        {
            EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
                .WillOnce([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                    EXPECT_EQ(3u, object_count);
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = i == 1 ? SAI_STATUS_FAILURE
                            : old_sai_route_api->set_route_entry_attribute(&route__entry[i], &attr_list[i]);
                    return SAI_STATUS_FAILURE;
                })
                .WillRepeatedly([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                    return old_sai_route_api->set_route_entries_attribute(SET_BULK_ATTR_ARGS(route));
                });
        }
        else
        {
            EXPECT_CALL(*mock_sai_route_api, remove_route_entries)
                .WillOnce([](REMOVE_BULK_PARAMS(route)) -> sai_status_t {
                    EXPECT_EQ(3u, object_count);
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = i == 1 ? SAI_STATUS_FAILURE
                            : old_sai_route_api->remove_route_entry(&route_entry[i]);
                    return SAI_STATUS_FAILURE;
                });
        }
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_NE(nullptr, m_MuxCable->acl_handler_);
        EXPECT_EQ(selected, m_MuxCable->nbr_handler_->neighbors_);
        EXPECT_EQ(refs, RifRefs());
        for (const auto& old : selected)
        {
            EXPECT_EQ(old.second, RouteNextHop(old.first.to_string()));
        }
    }

    TEST_P(MuxTransitionModesTest, EcmpCreateFailureCompensatesOnlyChangedMembers)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        NextHopGroupKey group("192.168.0.2@Vlan1000,192.168.0.3@Vlan1000,192.168.0.4@Vlan1000");
        ASSERT_TRUE(gRouteOrch->addNextHopGroup(group));
        string previous = ACTIVE_STATE;
        string target = STANDBY_STATE;
        if (GetParam() == "prefix-route")
        {
            SetAndAssertMuxState(STANDBY_STATE);
            previous = STANDBY_STATE;
            target = ACTIVE_STATE;
        }
        auto before = gNeighOrch->m_syncdNextHops;
        auto old_group = gRouteOrch->m_syncdNextHopGroups.at(group);
        int creates = 0;
        EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member)
            .WillRepeatedly([&](GENERIC_CREATE_PARAMS(next_hop_group_member)) -> sai_status_t {
                if (creates++ == 1)
                {
                    *next_hop_group_member_id = SAI_NULL_OBJECT_ID;
                    return SAI_STATUS_FAILURE;
                }
                return old_sai_next_hop_group_api->create_next_hop_group_member(
                    GENERIC_CREATE_ARGS(next_hop_group_member));
            });
        SetMuxStateFromAppDb(target);
        EXPECT_GE(creates, 2);
        EXPECT_EQ(previous, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(old_group.nh_member_install_count, gRouteOrch->m_syncdNextHopGroups.at(group).nh_member_install_count);
        for (const auto& nh : before)
        {
            EXPECT_EQ(nh.second.next_hop_id, gNeighOrch->getLocalNextHopId(nh.first));
            EXPECT_EQ(nh.second.ref_count, gNeighOrch->getNextHopRefCount(nh.first));
        }
        EXPECT_EQ(old_group.nhopgroup_members.at(Key("192.168.0.4")).next_hop_id,
                  gRouteOrch->m_syncdNextHopGroups.at(group).nhopgroup_members.at(Key("192.168.0.4")).next_hop_id);
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_group_api);
        ASSERT_TRUE(gRouteOrch->removeNextHopGroup(group));
    }

    TEST_P(MuxTransitionModesTest, MissingSliceTunnelStopsBeforeRemovingTheLiveAnchor)
    {
        ThreeNeighbors();
        NeighborEvent("a::a");
        m_MuxCable->slice_ip6_ = IpPrefix("a::/64");
        ASSERT_TRUE(m_MuxCable->refreshSliceRoute());
        SetAndAssertMuxState(ACTIVE_STATE);
        AddEcmpRoute("10.84.0.0/24");
        const auto anchor = gNeighOrch->getLocalNextHopId(Key("a::a"));
        ASSERT_EQ(anchor, RouteNextHop("a::/64"));
        const auto peer = m_MuxCable->peer_ip4_;
        const auto saved = m_MuxOrch->mux_tunnel_nh_.at(peer);
        const auto baseline = CrmUsed();
        bool withdrew = false;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            const auto status = old_sai_route_api->set_route_entry_attribute(entry, attr);
            if (!withdrew && status == SAI_STATUS_SUCCESS &&
                sai_serialize_ip_prefix(entry->destination) == "10.84.0.0/24" &&
                attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID && attr->value.oid == saved.nh_id)
            {
                m_MuxOrch->mux_tunnel_nh_.erase(peer);
                withdrew = true;
            }
            return status;
        };
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops).Times(0);
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_TRUE(withdrew);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_EQ(anchor, RouteNextHop("a::/64"));
        EXPECT_EQ(anchor, gNeighOrch->getLocalNextHopId(Key("a::a")));
        EXPECT_TRUE(gNeighOrch->isHwConfigured(Key("a::a")));
        EXPECT_EQ(baseline, CrmUsed());
        m_MuxOrch->mux_tunnel_nh_.emplace(peer, saved);
        route_set = {};
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_api);
        SetAndAssertMuxState(STANDBY_STATE);
        EXPECT_EQ(saved.nh_id, RouteNextHop("a::/64"));
        SetAndAssertMuxState(ACTIVE_STATE);
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key("a::a")), RouteNextHop("a::/64"));
        DeleteRoute("10.84.0.0/24");
    }

    TEST_P(MuxTransitionModesTest, SliceRouteDoesNotRetainARemovedAnchorNextHop)
    {
        NeighborEvent("a::a");
        m_MuxCable->slice_ip6_ = IpPrefix("a::/64");
        ASSERT_TRUE(m_MuxCable->refreshSliceRoute());
        SetAndAssertMuxState(ACTIVE_STATE);
        auto old_anchor = gNeighOrch->getLocalNextHopId(Key("a::a"));
        ASSERT_EQ(old_anchor, RouteNextHop("a::/64"));
        auto crm = CrmUsed();
        int refs = RifRefs();
        if (GetParam() == "host-route")
        {
            EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
                .WillOnce([](GENERIC_BULK_REMOVE_PARAMS(next_hop)) -> sai_status_t {
                    auto result = old_sai_next_hop_api->remove_next_hops(GENERIC_BULK_REMOVE_ARGS(next_hop));
                    for (uint32_t i = 0; i < object_count; ++i)
                    {
                        EXPECT_EQ(SAI_STATUS_SUCCESS, object_statuses[i]);
                    }
                    return result;
                });
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) -> sai_status_t {
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = sai_serialize_ip_address(neighbor_entry[i].ip_address) == "a::a"
                            ? SAI_STATUS_FAILURE : old_sai_neighbor_api->remove_neighbor_entry(&neighbor_entry[i]);
                    return SAI_STATUS_FAILURE;
                });
        }
        else
        {
            EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
                .WillOnce([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = i == 0 ? SAI_STATUS_FAILURE
                            : old_sai_route_api->set_route_entry_attribute(&route__entry[i], &attr_list[i]);
                    return SAI_STATUS_FAILURE;
                })
                .WillRepeatedly([](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                    return old_sai_route_api->set_route_entries_attribute(SET_BULK_ATTR_ARGS(route));
                });
        }
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        auto restored = gNeighOrch->getLocalNextHopId(Key("a::a"));
        EXPECT_EQ(restored, RouteNextHop("a::/64"));
        EXPECT_EQ(restored, m_MuxCable->slice_route_nh_oid_);
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        if (GetParam() == "host-route")
            ExpectRemovedNextHop(old_anchor);
    }

    TEST_P(MuxTransitionModesTest, InterfaceDownMembersRetainOnlyTheirLogicalReferences)
    {
        ThreeNeighbors();
        SetAndAssertMuxState(ACTIVE_STATE);
        NextHopGroupKey group("192.168.0.2@Vlan1000,192.168.0.3@Vlan1000,192.168.0.4@Vlan1000");
        ASSERT_TRUE(gRouteOrch->addNextHopGroup(group));
        Port vlan;
        ASSERT_TRUE(gPortsOrch->getPort(VLAN_1000, vlan));
        vlan.m_oper_status = SAI_PORT_OPER_STATUS_DOWN;
        gPortsOrch->setPort(VLAN_1000, vlan);
        for (const auto& member : m_MuxCable->nbr_handler_->neighbors_)
        {
            ASSERT_TRUE(gNeighOrch->setNextHopFlag(Key(member.first.to_string()), NHFLAGS_IFDOWN));
        }
        auto before = gNeighOrch->m_syncdNextHops;
        auto crm = CrmUsed();
        ASSERT_EQ(0u, gRouteOrch->m_syncdNextHopGroups.at(group).nh_member_install_count);
        EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member)
            .Times(GetParam() == "host-route" ? 3 : 0);
        SetAndAssertMuxState(STANDBY_STATE);
        SetAndAssertMuxState(ACTIVE_STATE);
        EXPECT_EQ(crm, CrmUsed());
        for (const auto& nh : before)
        {
            EXPECT_EQ(nh.second.ref_count, gNeighOrch->getNextHopRefCount(nh.first));
            EXPECT_TRUE(gNeighOrch->isNextHopFlagSet(nh.first, NHFLAGS_IFDOWN));
            EXPECT_EQ(SAI_NULL_OBJECT_ID, gRouteOrch->m_syncdNextHopGroups.at(group).nhopgroup_members.at(nh.first).next_hop_id);
        }
        ASSERT_TRUE(gRouteOrch->removeNextHopGroup(group));
        for (const auto& nh : before)
        {
            EXPECT_EQ(nh.second.ref_count - 1, gNeighOrch->getNextHopRefCount(nh.first));
        }
    }

    INSTANTIATE_TEST_SUITE_P(HostAndPrefix, MuxTransitionModesTest,
                            testing::Values(string("host-route"), string("prefix-route")));

    TEST_F(MuxPrefixRecoveryTest, CompensationExceptionClearsBulkPointersBeforeContinuing)
    {
        ThreeNeighbors();
        auto selected = m_MuxCable->nbr_handler_->neighbors_;
        int calls = 0;
        EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
            .WillRepeatedly([&](SET_BULK_ATTR_PARAMS(route)) -> sai_status_t {
                ++calls;
                EXPECT_EQ(calls == 1 ? 3u : 1u, object_count);
                if (calls == 2)
                    throw runtime_error("prefix compensation interrupted");
                bool failed = false;
                for (uint32_t i = 0; i < object_count; ++i)
                {
                    object_statuses[i] = calls == 1 && i == 1 ? SAI_STATUS_FAILURE
                        : old_sai_route_api->set_route_entry_attribute(&route__entry[i], &attr_list[i]);
                    failed = failed || object_statuses[i] != SAI_STATUS_SUCCESS;
                }
                return failed ? SAI_STATUS_FAILURE : SAI_STATUS_SUCCESS;
            });
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_EQ(4, calls);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        auto handler = m_MuxCable->nbr_handler_.get();
        EXPECT_TRUE(handler->gRouteBulker.setting_entries.empty());
        EXPECT_TRUE(handler->gRouteBulker.creating_entries.empty());
        EXPECT_TRUE(handler->gRouteBulker.removing_entries.empty());
        EXPECT_TRUE(handler->transition_.at(IpAddress(SERVER_IP1)).host_route_unknown);
        EXPECT_FALSE(handler->transition_.at(IpAddress(SERVER_IP1)).rollback_done);
        for (const string ip : {"192.168.0.3", "192.168.0.4"})
        {
            EXPECT_FALSE(handler->transition_.at(IpAddress(ip)).host_route_unknown);
            EXPECT_TRUE(handler->transition_.at(IpAddress(ip)).rollback_done);
            EXPECT_EQ(selected.at(IpAddress(ip)), RouteNextHop(ip));
        }

        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        RecoveryDue();
        DispatchMux();
        EXPECT_EQ(5, calls); // Only the unconfirmed member is retried.
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_TRUE(handler->gRouteBulker.setting_entries.empty());
        for (const auto& neighbor : selected)
        {
            EXPECT_EQ(neighbor.second, RouteNextHop(neighbor.first.to_string()));
        }
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
        EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
    }

    TEST_F(MuxSharedCableTest, MultiMuxRoutesRedirectBeforeOwnedNextHopCleanup)
    {
        ThreeNeighbors();
        SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
        ASSERT_EQ(ACTIVE_STATE, m_MuxOrch->getMuxCable("Ethernet8")->getState());
        MultiMuxRoute("10.9.0.0/24");
        auto previous_target = RouteNextHop("10.9.0.0/24");
        ASSERT_EQ(gNeighOrch->getLocalNextHopId(Key("192.168.1.2")), previous_target);
        int refs = RifRefs();
        auto crm = CrmUsed();
        bool used_owned_next_hop = false;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (sai_serialize_ip_prefix(entry->destination) == "10.9.0.0/24" &&
                attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID &&
                attr->value.oid == gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)))
                used_owned_next_hop = true;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        FailOneNeighborCreate();
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .Times(3)
            .WillRepeatedly([&](sai_object_id_t oid) -> sai_status_t {
                EXPECT_NE(oid, RouteNextHop("10.9.0.0/24"));
                return old_sai_next_hop_api->remove_next_hop(oid);
            });
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_TRUE(used_owned_next_hop);
        EXPECT_EQ(previous_target, RouteNextHop("10.9.0.0/24"));
        ExpectStandbyRestored(refs);
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_F(MuxSharedCableTest, FailedMultiMuxRedirectionRetainsOwnershipUntilDispatcherRetry)
    {
        ThreeNeighbors();
        SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
        MultiMuxRoute("10.9.0.0/24");
        auto previous_target = RouteNextHop("10.9.0.0/24");
        int refs = RifRefs();
        auto crm = CrmUsed();
        bool forward_seen = false;
        bool block_restore = true;
        int removals = 0;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (sai_serialize_ip_prefix(entry->destination) == "10.9.0.0/24" &&
                attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
            {
                if (attr->value.oid == gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)))
                    forward_seen = true;
                if (forward_seen && attr->value.oid == previous_target && block_restore)
                    return SAI_STATUS_FAILURE;
            }
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        FailOneNeighborCreate();
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .WillRepeatedly([&](sai_object_id_t oid) -> sai_status_t {
                ++removals;
                EXPECT_NE(oid, RouteNextHop("10.9.0.0/24"));
                return old_sai_next_hop_api->remove_next_hop(oid);
            });
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(forward_seen);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(0, removals);
        auto owned = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, owned);
        EXPECT_EQ(owned, RouteNextHop("10.9.0.0/24"));
        EXPECT_EQ(1u, PendingMuxRequest());
        EXPECT_TRUE(m_MuxCableOrch->recovery_timer_running_);

        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        block_restore = false;
        RecoveryDue();
        DispatchMux();
        EXPECT_EQ(3, removals);
        EXPECT_EQ(previous_target, RouteNextHop("10.9.0.0/24"));
        ExpectRemovedNextHop(owned);
        ExpectStandbyRestored(refs);
        EXPECT_EQ(crm, CrmUsed());
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
    }

    TEST_F(MuxSharedCableTest, LaterMultiMuxRouteFailureRestoresEveryRouteBeforeCleanup)
    {
        SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
        MultiMuxRoute("10.9.0.0/24");
        MultiMuxRoute("10.10.0.0/24");
        auto previous_target = RouteNextHop("10.9.0.0/24");
        bool earlier_changed = false;
        bool later_failed = false;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID &&
                attr->value.oid == gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)))
            {
                auto prefix = sai_serialize_ip_prefix(entry->destination);
                if (prefix == "10.9.0.0/24")
                    earlier_changed = true;
                if (prefix == "10.10.0.0/24")
                {
                    later_failed = true;
                    return SAI_STATUS_FAILURE;
                }
            }
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .Times(1)
            .WillOnce([&](sai_object_id_t oid) -> sai_status_t {
                EXPECT_NE(oid, RouteNextHop("10.9.0.0/24"));
                EXPECT_NE(oid, RouteNextHop("10.10.0.0/24"));
                return old_sai_next_hop_api->remove_next_hop(oid);
            });
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_TRUE(earlier_changed);
        EXPECT_TRUE(later_failed);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(previous_target, RouteNextHop("10.9.0.0/24"));
        EXPECT_EQ(previous_target, RouteNextHop("10.10.0.0/24"));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
    }

    TEST_F(MuxSharedCableTest, SharedAclUnbindFailurePreservesHardwareAndSoftwarePorts)
    {
        auto both = SoftwareAclPorts();
        ASSERT_EQ(2u, both.size());
        ASSERT_EQ(both, HardwareAclPorts());
        auto oid = SharedRule()->getOid();
        int failures = 0;
        acl_set = [&](sai_object_id_t entry, const sai_attribute_t* attr) -> sai_status_t {
            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS && failures++ == 0)
            {
                EXPECT_EQ(oid, entry);
                EXPECT_EQ(both, SoftwareAclPorts());
                EXPECT_EQ(both, HardwareAclPorts());
                return SAI_STATUS_FAILURE;
            }
            return old_sai_acl_api->set_acl_entry_attribute(entry, attr);
        };
        SetMuxStateFromAppDb(ACTIVE_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_EQ(SAI_STATUS_FAILURE, SharedRule()->getLastSaiStatus());
        EXPECT_EQ(both, SoftwareAclPorts());
        EXPECT_EQ(both, HardwareAclPorts());
        EXPECT_TRUE(m_MuxCable->acl_handler_->bound_);

        SetMuxStateFromAppDb(ACTIVE_STATE);
        vector<sai_object_id_t> other{PortOid("Ethernet8")};
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_EQ(oid, SharedRule()->getOid());
        EXPECT_EQ(other, SoftwareAclPorts());
        EXPECT_EQ(other, HardwareAclPorts());
    }

    TEST_F(MuxSharedCableTest, SharedAclBindFailureDuringRecoveryIsRetriedWithoutSoftwareDrift)
    {
        auto both = SoftwareAclPorts();
        vector<sai_object_id_t> other{PortOid("Ethernet8")};
        bool block_bind = true;
        int creates = 0;
        int removals = 0;
        bool block_cleanup = false;
        HoldFirstEnableCleanup(block_cleanup, creates, removals);
        acl_set = [&](sai_object_id_t entry, const sai_attribute_t* attr) -> sai_status_t {
            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS &&
                attr->value.aclfield.data.objlist.count == 2 && block_bind)
            {
                EXPECT_EQ(other, SoftwareAclPorts());
                EXPECT_EQ(other, HardwareAclPorts());
                return SAI_STATUS_FAILURE;
            }
            return old_sai_acl_api->set_acl_entry_attribute(entry, attr);
        };
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(SAI_STATUS_FAILURE, SharedRule()->getLastSaiStatus());
        EXPECT_EQ(other, SoftwareAclPorts());
        EXPECT_EQ(other, HardwareAclPorts());
        EXPECT_EQ(nullptr, m_MuxCable->acl_handler_);
        EXPECT_EQ(1u, PendingMuxRequest());

        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        block_bind = false;
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(both, SoftwareAclPorts());
        EXPECT_EQ(both, HardwareAclPorts());
        EXPECT_EQ(1, creates);
        EXPECT_EQ(1, removals);
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
    }

    TEST_F(MuxSharedCableTest, NoUsableActiveNextHopLegitimatelyUsesTunnel)
    {
        MultiMuxRoute("10.9.0.0/24");
        auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        int sets = 0;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            ++sets;
            EXPECT_EQ(tunnel, attr->value.oid);
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_TRUE(m_MuxOrch->updateRoute(IpPrefix("10.9.0.0/24")));
        EXPECT_EQ(1, sets);
        EXPECT_EQ(tunnel, RouteNextHop("10.9.0.0/24"));
    }

    TEST_F(MuxSharedCableTest, SelectedActiveNextHopFailureDoesNotTrySuccessfulTunnelFallback)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        MultiMuxRoute("10.9.0.0/24");
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        int active_attempts = 0;
        int fallback_attempts = 0;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (attr->value.oid == local)
            {
                ++active_attempts;
                return SAI_STATUS_FAILURE;
            }
            if (attr->value.oid == tunnel)
                ++fallback_attempts;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_FALSE(m_MuxOrch->updateRoute(IpPrefix("10.9.0.0/24")));
        EXPECT_EQ(1, active_attempts);
        EXPECT_EQ(0, fallback_attempts);
        EXPECT_EQ(local, RouteNextHop("10.9.0.0/24"));
    }

    TEST_F(MuxSharedCableTest, MissingFallbackTunnelCannotProgramNullOrReportSuccess)
    {
        MultiMuxRoute("10.9.0.0/24");
        auto previous = RouteNextHop("10.9.0.0/24");
        auto tunnels = m_MuxOrch->mux_tunnel_nh_;
        m_MuxOrch->mux_tunnel_nh_.clear();
        int sets = 0;
        route_set = [&](const sai_route_entry_t*, const sai_attribute_t*) -> sai_status_t {
            ++sets;
            return SAI_STATUS_SUCCESS;
        };
        EXPECT_FALSE(m_MuxOrch->updateRoute(IpPrefix("10.9.0.0/24")));
        EXPECT_EQ(0, sets);
        EXPECT_EQ(previous, RouteNextHop("10.9.0.0/24"));
        m_MuxOrch->mux_tunnel_nh_ = std::move(tunnels);
    }

    TEST_F(MuxHybridTest, RetainedOriginalRequestReachesTargetAfterTransientRecoveryFailure)
    {
        bool blocked = true;
        int creates = 0;
        int removals = 0;
        HoldFirstEnableCleanup(blocked, creates, removals);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        ASSERT_EQ(1u, PendingMuxRequest());
        EXPECT_TRUE(m_MuxCableOrch->recovery_timer_running_);
        EXPECT_EQ(1, creates);
        EXPECT_EQ(1, removals);

        blocked = false;
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_EQ(1, creates);
        EXPECT_EQ(1u, PendingMuxRequest());
        ExpectNeighborHardware(SERVER_IP1, false);
        DispatchMux();
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCable->isStateChangeInProgress());
        EXPECT_EQ(2, creates);
        EXPECT_EQ(0u, PendingMuxRequest());
        ExpectNeighborHardware(SERVER_IP1, true);
        EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
        RecoveryTimerTick();
        EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
    }

    TEST_F(MuxHybridTest, RecoveryBackoffBoundsWorkAndReplacementTargetCannotDiscardCleanup)
    {
        bool blocked = true;
        int creates = 0;
        int removals = 0;
        HoldFirstEnableCleanup(blocked, creates, removals);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        ASSERT_FALSE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
        auto owner = m_MuxCable->nbr_handler_->neighbor_contexts_.front().neighborEntry;
        EXPECT_EQ(2, m_MuxCable->recovery_retry_delay_.count());
        for (int attempt = 0; attempt < 6; ++attempt)
        {
            auto delay = m_MuxCable->recovery_retry_delay_;
            RecoveryDue();
            DispatchMux();
            EXPECT_EQ(std::min(delay * 2, std::chrono::seconds(30)), m_MuxCable->recovery_retry_delay_);
        }
        EXPECT_EQ(30, m_MuxCable->recovery_retry_delay_.count());
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        auto deadline = m_MuxCable->recovery_retry_at_;
        auto metrics = TableFields(m_MuxCableOrch->mux_metric_table_);
        int previous_removals = removals;
        for (int i = 0; i < 10; ++i)
            DispatchMux();
        SetMuxStateFromAppDb("invalid");
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(previous_removals, removals);
        EXPECT_EQ(1, creates);
        EXPECT_EQ(deadline, m_MuxCable->recovery_retry_at_);
        EXPECT_EQ(metrics, TableFields(m_MuxCableOrch->mux_metric_table_));
        EXPECT_EQ(owner, m_MuxCable->nbr_handler_->neighbor_contexts_.front().neighborEntry);
        EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.front().neighbor_created);
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(1u, PendingMuxRequest());
        ExpectNeighborHardware(SERVER_IP1, true);

        blocked = false;
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_EQ(1, creates);
        EXPECT_EQ(1u, PendingMuxRequest());
        ExpectNeighborHardware(SERVER_IP1, false);
        DispatchMux();
        EXPECT_EQ(0u, PendingMuxRequest());
        RecoveryTimerTick();
        EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
    }

    TEST_F(MuxHybridTest, RecoveryTimerFinishesOwnedCleanupAfterRequestDeletion)
    {
        bool blocked = true;
        int creates = 0;
        int removals = 0;
        HoldFirstEnableCleanup(blocked, creates, removals);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        Table desired(m_app_db.get(), APP_MUX_CABLE_TABLE_NAME);
        desired.del(TEST_INTERFACE);
        auto consumer = m_MuxCableOrch->getConsumerBase(APP_MUX_CABLE_TABLE_NAME);
        consumer->addToSync(KeyOpFieldsValuesTuple(TEST_INTERFACE, DEL_COMMAND, vector<FieldValueTuple>{}));
        DispatchMux();
        ASSERT_EQ(0u, PendingMuxRequest());
        EXPECT_TRUE(m_MuxCableOrch->recovery_timer_running_);
        EXPECT_EQ(1u, m_MuxCableOrch->recovery_ports_.count(TEST_INTERFACE));
        blocked = false;
        RecoveryDue();
        RecoveryTimerTick();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_FALSE(m_MuxCableOrch->recovery_timer_running_);
        EXPECT_TRUE(m_MuxCableOrch->recovery_ports_.empty());
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_EQ(1, creates);
        ExpectNeighborHardware(SERVER_IP1, false);
    }

    TEST_P(MuxTransitionModesTest, AuthoritativeDeleteDuringActiveRecoveryDoesNotResurrect)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseActiveNeighborRetirement(false, false));
    }

    TEST_P(MuxTransitionModesTest, SameMacReaddDuringActiveRecoveryPreservesNewIncarnation)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseActiveNeighborRetirement(true, false));
    }

    TEST_P(MuxTransitionModesTest, ChangedMacReaddDuringActiveRecoveryPreservesReplacement)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseActiveNeighborRetirement(true, true));
    }

    TEST_P(MuxTransitionModesTest, SameMacSetRepairsPartialDeleteAndSupersedesOldRecovery)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        auto original = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1));
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
            .Times(2)
            .WillRepeatedly(Return(SAI_STATUS_FAILURE));
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + SERVER_IP1;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, vector<FieldValueTuple>{}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_),
                  m_MuxCable->getNextHopId(Key(SERVER_IP1)));
        ASSERT_FALSE(original.incarnation->retired);
        NeighborEvent(SERVER_IP1, true, original.mac.to_string());
        ASSERT_TRUE(original.incarnation->retired);
        auto replacement = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, replacement);
        EXPECT_EQ(replacement, m_MuxCable->nbr_handler_->neighbors_.at(IpAddress(SERVER_IP1)));
        auto crm = CrmUsed();
        int refs = RifRefs();
        int prior_attempts = attempts;
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_attempts, attempts);
        EXPECT_EQ(replacement, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        ExpectNeighborHardware(SERVER_IP1, true);
        testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_F(MuxHybridTest, AuthoritativeDeleteDuringOwnedCleanupDoesNotDoubleAccount)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseStandbyNeighborRetirement(false, false));
    }

    TEST_F(MuxHybridTest, AuthoritativeDeleteCannotConfirmUnacknowledgedBulkOutcome)
    {
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
            .WillOnce(Throw(std::runtime_error("completion unavailable")));
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        ASSERT_FALSE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
        ASSERT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.front().result_unknown);
        auto incarnation = m_MuxCable->nbr_handler_->neighbor_contexts_.front().incarnation;
        NeighborEvent(SERVER_IP1, false);
        ASSERT_TRUE(incarnation->retired);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hops).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).Times(0);
        RecoveryDue();
        DispatchMux();
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_EQ(1u, PendingMuxRequest());
        EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.front().result_unknown);
    }

    TEST_F(MuxPrefixRecoveryTest, ReplacementPrefixFailureRetainsNewPrimaryObjectsForNativeRetry)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        auto original = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        auto crm = CrmUsed();
        int refs = RifRefs();
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        NeighborEvent(SERVER_IP1, false);
        ASSERT_TRUE(original->retired);
        EXPECT_CALL(*mock_sai_route_api, create_route_entry)
            .WillOnce(Return(SAI_STATUS_TABLE_FULL));
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + SERVER_IP1;
        vector<FieldValueTuple> fields{{"neigh", MAC4}, {"family", "IPv4"}};
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND, fields));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        auto replacement = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(original, replacement);
        ASSERT_NE(SAI_NULL_OBJECT_ID, local);
        ASSERT_TRUE(replacement->prefix_pending);
        EXPECT_FALSE(replacement->prefix_owned);
        ExpectNeighborHardware(SERVER_IP1, true);
        RecoveryDue();
        DispatchMux();
        EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(local, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_FALSE(replacement->retired);
        testing::Mock::VerifyAndClearExpectations(mock_sai_route_api);
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_EQ(replacement, gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation);
        EXPECT_EQ(local, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_FALSE(replacement->prefix_pending);
        EXPECT_TRUE(replacement->prefix_owned);
        EXPECT_EQ(local, RouteNextHop(SERVER_IP1));
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_api);
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
    }

    TEST_F(MuxHybridTest, SameMacReaddDuringOwnedCleanupIsNotDeleted)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseStandbyNeighborRetirement(true, false));
    }

    TEST_F(MuxPrefixRecoveryTest, CancelledReplacementCannotDeleteUnownedExistingPrefix)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        NeighborEvent(SERVER_IP1, false);
        NeighborEvent("192.168.0.3");
        const string prefix = SERVER_IP1 + "/32";
        AddRoute(prefix, "192.168.0.3");
        auto target = RouteNextHop(prefix);
        auto generation = gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix(prefix)).generation;
        auto crm = CrmUsed();
        int refs = RifRefs();
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + SERVER_IP1;
        vector<FieldValueTuple> fields{{"neigh", MAC4}, {"family", "IPv4"}};
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND, fields));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        auto replacement = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        EXPECT_TRUE(replacement->prefix_pending);
        EXPECT_FALSE(replacement->prefix_owned);
        EXPECT_EQ(target, RouteNextHop(prefix));
        EXPECT_CALL(*mock_sai_route_api, remove_route_entry).Times(0);
        NeighborEvent(SERVER_IP1, false);
        EXPECT_TRUE(replacement->retired);
        EXPECT_EQ(target, RouteNextHop(prefix));
        EXPECT_EQ(generation, gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix(prefix)).generation);
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        testing::Mock::VerifyAndClearExpectations(mock_sai_route_api);
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(target, RouteNextHop(prefix));
    }

    TEST_F(MuxHybridTest, ChangedMacReaddDuringOwnedCleanupIsNotDeleted)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseStandbyNeighborRetirement(true, true));
    }

    TEST_F(MuxHybridTest, NormalDeleteAccountsIndependentNextHopBeforeRetiringCleanup)
    {
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entries)
            .WillOnce([](CREATE_BULK_PARAMS(neighbor)) -> sai_status_t {
                for (uint32_t i = 0; i < object_count; ++i)
                    object_statuses[i] = SAI_STATUS_FAILURE;
                return SAI_STATUS_FAILURE;
            });
        bool blocked = true;
        int removes = 0;
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .WillRepeatedly([&](sai_object_id_t oid) -> sai_status_t {
                ++removes;
                return blocked ? SAI_STATUS_FAILURE : old_sai_next_hop_api->remove_next_hop(oid);
            });
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        auto owned = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, owned);
        ASSERT_FALSE(gNeighOrch->isHwConfigured(Key(SERVER_IP1)));
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        blocked = false;
        NeighborEvent(SERVER_IP1, false);
        ASSERT_TRUE(incarnation->retired);
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        ExpectRemovedNextHop(owned);
        int refs = RifRefs();
        auto crm = CrmUsed();
        int prior_removes = removes;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_removes, removes);
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(Key(SERVER_IP1)));
    }

    TEST_F(MuxHybridTest, AuthoritativeMacReplacementAdoptsOwnedObjectsBeforeRetry)
    {
        AddRoute("10.30.0.0/24", SERVER_IP1);
        int baseline_refs = RifRefs();
        auto baseline_crm = CrmUsed();
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).incarnation;
        auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        route_set = [tunnel](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (sai_serialize_ip_prefix(entry->destination) == "10.30.0.0/24" && attr->value.oid != tunnel)
                return SAI_STATUS_FAILURE;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        int removes = 0;
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop)
            .WillRepeatedly([&](sai_object_id_t) -> sai_status_t {
                ++removes;
                return SAI_STATUS_FAILURE;
            });
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        auto adopted = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_NE(SAI_NULL_OBJECT_ID, adopted);
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        NeighborEvent(SERVER_IP1, true, MAC5);
        ASSERT_TRUE(incarnation->retired);
        ASSERT_EQ(adopted, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        auto crm = CrmUsed();
        int refs = RifRefs();
        int prior_removes = removes;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_removes, removes);
        EXPECT_EQ(adopted, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        EXPECT_EQ(MacAddress(MAC5), gNeighOrch->getNeighborTable().at(Key(SERVER_IP1)).mac);
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        ExpectNeighborHardware(SERVER_IP1, true);
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_api);
        route_set = {};
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        SetMuxStateFromAppDb(STANDBY_STATE);
        EXPECT_EQ(STANDBY_STATE, m_MuxCable->getState());
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_EQ(baseline_refs, RifRefs());
        EXPECT_EQ(baseline_crm, CrmUsed());
    }

    TEST_F(MuxHybridTest, RouteAddedBeforeLocalNextHopRecoveryConvergesToCurrentRole)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        AddRoute("10.22.0.0/24", SERVER_IP1);
        auto generation = gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix("10.22.0.0/24")).generation;
        EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_), RouteNextHop("10.22.0.0/24"));
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)), RouteNextHop("10.22.0.0/24"));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(generation, gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix("10.22.0.0/24")).generation);
        auto crm = CrmUsed();
        int refs = RifRefs();
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_P(MuxTransitionModesTest, RecoveryAddsOnlyItsMissingReferenceAfterNewRouteArrival)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        ASSERT_EQ(0, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        AddRoute("10.20.1.0/24", SERVER_IP1);
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        ASSERT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        for (int i = 0; i < 3; ++i)
        {
            RecoveryDue();
            DispatchMux();
            EXPECT_TRUE(m_MuxCable->isStateChangeFailed());
            EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
            EXPECT_EQ(local, RouteNextHop("10.20.1.0/24"));
        }
        auto crm = CrmUsed();
        int refs = RifRefs();
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(local, RouteNextHop("10.20.0.0/24"));
        EXPECT_EQ(local, RouteNextHop("10.20.1.0/24"));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_P(MuxTransitionModesTest, DeletingPendingRouteCannotStealNewRoutesReference)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        AddRoute("10.20.1.0/24", SERVER_IP1);
        DeleteRoute("10.20.0.0/24");
        ASSERT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        int prior_restores = restores;
        auto crm = CrmUsed();
        int refs = RifRefs();
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_restores, restores);
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_FALSE(gRouteOrch->isRouteExists(gVirtualRouterId, IpPrefix("10.20.0.0/24")));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
    }

    TEST_P(MuxTransitionModesTest, ReplacementNextHopSupersedesPendingRouteRecovery)
    {
        NeighborEvent("192.168.0.3");
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        AddRoute("10.20.1.0/24", SERVER_IP1);
        AddRoute("10.20.0.0/24", "192.168.0.3");
        auto replacement = gNeighOrch->getLocalNextHopId(Key("192.168.0.3"));
        int prior_restores = restores;
        auto crm = CrmUsed();
        int refs = RifRefs();
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_restores, restores);
        EXPECT_EQ(replacement, RouteNextHop("10.20.0.0/24"));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
    }

    TEST_P(MuxTransitionModesTest, NewEcmpReplacementIsNotReplayedByOldRecovery)
    {
        NeighborEvent("192.168.0.3");
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        AddRoute("10.20.1.0/24", SERVER_IP1);
        blocked = false;
        AddEcmpRoute("10.20.0.0/24");
        auto key = gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix("10.20.0.0/24"));
        auto members = gRouteOrch->m_syncdNextHopGroups.at(key).nhopgroup_members;
        auto replacement = RouteNextHop("10.20.0.0/24");
        auto crm = CrmUsed();
        int refs = RifRefs();
        int prior_restores = restores;
        EXPECT_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member).Times(0);
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        // The outer MUX projection reconciles the current ECMP route once; the old direct-route debt is retired.
        EXPECT_EQ(prior_restores + 1, restores);
        EXPECT_EQ(replacement, RouteNextHop("10.20.0.0/24"));
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        for (const auto& member : members)
        {
            EXPECT_EQ(member.second.next_hop_id,
                      gRouteOrch->m_syncdNextHopGroups.at(key).nhopgroup_members.at(member.first).next_hop_id);
        }
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_group_api);
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
    }

    TEST_P(MuxTransitionModesTest, SamePrefixReaddIsANewRouteIncarnation)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        auto original = gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix("10.20.0.0/24")).generation;
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        AddRoute("10.20.1.0/24", SERVER_IP1);
        DeleteRoute("10.20.0.0/24");
        AddRoute("10.20.0.0/24", SERVER_IP1);
        ASSERT_NE(original, gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(IpPrefix("10.20.0.0/24")).generation);
        ASSERT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        int prior_restores = restores;
        auto crm = CrmUsed();
        int refs = RifRefs();
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_restores, restores);
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)), RouteNextHop("10.20.0.0/24"));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
    }

    TEST_P(MuxTransitionModesTest, RecreatedEcmpGroupWithSameKeyIsNotOwnedByOldRecovery)
    {
        NeighborEvent("192.168.0.3");
        SetAndAssertMuxState(ACTIVE_STATE);
        AddRoute("10.20.0.0/24", SERVER_IP1);
        AddEcmpRoute("10.20.2.0/24");
        auto key = gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, IpPrefix("10.20.2.0/24"));
        auto original = gRouteOrch->m_syncdNextHopGroups.at(key).generation;
        bool blocked = true;
        int restores = 0;
        ASSERT_NO_FATAL_FAILURE(HoldRouteRecovery("10.20.0.0/24", blocked, restores));
        DeleteRoute("10.20.2.0/24");
        ASSERT_FALSE(gRouteOrch->hasNextHopGroup(key));
        AddEcmpRoute("10.20.2.0/24");
        ASSERT_NE(original, gRouteOrch->m_syncdNextHopGroups.at(key).generation);
        auto members = gRouteOrch->m_syncdNextHopGroups.at(key).nhopgroup_members;
        auto crm = CrmUsed();
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member).Times(0);
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        for (const auto& member : members)
        {
            EXPECT_EQ(member.second.next_hop_id,
                      gRouteOrch->m_syncdNextHopGroups.at(key).nhopgroup_members.at(member.first).next_hop_id);
        }
        testing::Mock::VerifyAndClearExpectations(mock_sai_next_hop_group_api);
        ASSERT_NO_FATAL_FAILURE(RoundTripActive());
        EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key("192.168.0.3")));
    }

    TEST_F(MuxHybridTest, FgRecoveryFiltersSupersededRoutesWithoutDisablingCurrentCohort)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        const IpPrefix prefix("10.21.0.0/24");
        AddRoute(prefix.to_string(), SERVER_IP1);
        auto generation = gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(prefix).generation;
        MuxRouteJournal old{{{gVirtualRouterId, prefix}, {generation, true}}};
        DeleteRoute(prefix.to_string());
        AddRoute(prefix.to_string(), SERVER_IP1);
        auto current_generation = gRouteOrch->getSyncdRoutes().at(gVirtualRouterId).at(prefix).generation;
        ASSERT_NE(generation, current_generation);
        MuxRouteJournal current{{{gVirtualRouterId, prefix}, {current_generation, true}}};
        MuxNextHopGroups groups;

        // A newly discovered FG row must be filtered before its configuration or hardware is consulted.
        auto& fg_table = gFgNhgOrch->m_syncdFGRouteTables[gVirtualRouterId];
        ASSERT_EQ(0u, fg_table.count(prefix));
        FGNextHopGroupEntry entry{};
        entry.nhg_key = gRouteOrch->getSyncdRouteNhgKey(gVirtualRouterId, prefix);
        fg_table.emplace(prefix, entry);
        RouteKey route_key{gVirtualRouterId, prefix};
        gRouteOrch->removeNextHopRoute(Key(SERVER_IP1), route_key);
        MuxRouteJournal discovered;
        EXPECT_TRUE(gRouteOrch->updateMuxNextHopRoutes(Key(SERVER_IP1), discovered, false));
        EXPECT_EQ(current, discovered);
        gRouteOrch->addNextHopRoute(Key(SERVER_IP1), route_key);
        auto crm = CrmUsed();
        int refs = RifRefs();
        uint32_t count = 0;
        EXPECT_CALL(*mock_sai_next_hop_group_api, remove_next_hop_group_member).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_group_api, create_next_hop_group_member).Times(0);
        EXPECT_TRUE(gRouteOrch->invalidnexthopinNextHopGroup(Key(SERVER_IP1), count, true, true, &groups, &old));
        EXPECT_TRUE(gRouteOrch->validnexthopinNextHopGroup(Key(SERVER_IP1), count, true, true, &groups, &old));
        // Matching generations still reach normal FG validation, which must reject this unconfigured row.
        EXPECT_FALSE(gRouteOrch->validnexthopinNextHopGroup(Key(SERVER_IP1), count, true, true, &groups, &current));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        EXPECT_EQ(refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
        fg_table.erase(prefix);
        if (fg_table.empty())
            gFgNhgOrch->m_syncdFGRouteTables.erase(gVirtualRouterId);
    }

    TEST_P(MuxFgAdmissionTest, OutstandingCleanupGatesFgAcrossStandbyHandoff)
    {
        const string prefix = "10.60.0.0/24";
        bool blocked = true;
        int removals = 0;
        ASSERT_NO_FATAL_FAILURE(HoldOwnedHop(blocked, removals));
        ConfigureFg(prefix, moving_ip);
        auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
        consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND,
            vector<FieldValueTuple>{{"nexthop", moving_ip}, {"ifname", VLAN_1000}}));
        auto crm = CrmUsed();
        ASSERT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        static_cast<Orch*>(gRouteOrch)->doTask();
        EXPECT_EQ(1u, consumer->m_toSync.count(prefix));
        EXPECT_FALSE(gFgNhgOrch->syncdContainsFgNhg(gVirtualRouterId, IpPrefix(prefix)));
        EXPECT_EQ(0, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        EXPECT_EQ(crm, CrmUsed());
        if (get<0>(GetParam()))
        {
            SetFdb(moving_mac, "Ethernet8");
            ASSERT_FALSE(m_MuxOrch->getMuxCable("Ethernet8")->isStateChangeFailed());
            EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
            static_cast<Orch*>(gRouteOrch)->doTask();
            EXPECT_EQ(1u, consumer->m_toSync.count(prefix));
        }
        if (get<1>(GetParam()))
        {
            SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
            ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        }
        else
        {
            blocked = false;
            ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        }
        ASSERT_FALSE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        static_cast<Orch*>(gRouteOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        auto target = get<1>(GetParam()) ? gNeighOrch->getLocalNextHopId(Key(moving_ip))
            : m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        ASSERT_NO_FATAL_FAILURE(ExpectFgNextHop(prefix, target));
        EXPECT_EQ(get<1>(GetParam()) ? 2 : 0, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        if (get<1>(GetParam()))
        {
            blocked = false;
            ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
            EXPECT_EQ(target, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        }
        DeleteRoute(prefix);
        DeleteRoute("10.40.0.0/24");
        EXPECT_EQ(0, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        NeighborEvent(moving_ip, false);
    }

    INSTANTIATE_TEST_SUITE_P(ResourceOwners, MuxFgAdmissionTest,
        testing::Values(make_tuple(false, false), make_tuple(true, false), make_tuple(true, true)));

    TEST_F(MuxAssociationTest, RecoveryQueryDistinguishesConflictRetirementAndUnknown)
    {
        bool blocked = true;
        int removals = 0;
        ASSERT_NO_FATAL_FAILURE(HoldOwnedHop(blocked, removals));
        NeighborContext* ctx = nullptr;
        for (auto& candidate : m_MuxCable->nbr_handler_->neighbor_contexts_)
            if (candidate.neighborEntry == Key(moving_ip))
                ctx = &candidate;
        ASSERT_NE(nullptr, ctx);
        ASSERT_TRUE(ctx->nexthop_created);
        EXPECT_FALSE(m_MuxOrch->hasPendingNextHopRecovery(Key(SERVER_IP1)));
        auto saved = *ctx;
        ctx->next_hop_id = SAI_NULL_OBJECT_ID;
        ctx->incarnation = make_shared<NeighborIncarnation>();
        m_MuxCable->nbr_handler_->transition_.at(IpAddress(moving_ip)).transferred = true;
        EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        *ctx = saved;
        blocked = false;
        NeighborEvent(moving_ip, false);
        ASSERT_TRUE(ctx->incarnation->retired);
        ctx->nexthop_created = true;
        EXPECT_FALSE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        ctx->result_unknown = true;
        EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        ctx->result_unknown = false;
        ctx->nexthop_created = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
    }

    TEST_P(MuxNativeReceiverTest, NativeReceiverRepairsEitherIndependentPartialOutcome)
    {
        bool neighbor_present = get<0>(GetParam());
        bool repair_blocked = get<1>(GetParam());
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(neighbor_present, cleanup_blocked, true));
        const string multipath = "10.64.1.0/24";
        bool check_multipath = !neighbor_present && repair_blocked;
        if (check_multipath)
        {
            auto routes = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            routes->addToSync(KeyOpFieldsValuesTuple(multipath, SET_COMMAND,
                vector<FieldValueTuple>{{"nexthop", moving_ip + ",192.168.1.2"},
                    {"ifname", VLAN_1000 + "," + VLAN_1000}}));
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, routes->m_toSync.count(multipath));
        }
        auto original = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation;
        int refs = RifRefs();
        int created = 0;
        if (neighbor_present)
        {
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry).Times(0);
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
                .WillRepeatedly([&](sai_object_id_t* oid, sai_object_id_t sw, uint32_t count,
                                    const sai_attribute_t* attrs) -> sai_status_t {
                    if (repair_blocked)
                        return SAI_STATUS_TABLE_FULL;
                    auto status = old_sai_next_hop_api->create_next_hop(oid, sw, count, attrs);
                    if (status == SAI_STATUS_SUCCESS)
                        ++created;
                    return status;
                });
        }
        else
        {
            EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
            EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry)
                .WillRepeatedly([&](const sai_neighbor_entry_t* entry, uint32_t count,
                                    const sai_attribute_t* attrs) -> sai_status_t {
                    if (repair_blocked)
                        return SAI_STATUS_FAILURE;
                    auto status = old_sai_neighbor_api->create_neighbor_entry(entry, count, attrs);
                    if (status == SAI_STATUS_SUCCESS)
                        ++created;
                    return status;
                });
        }
        SetFdb(moving_mac, "Ethernet8");
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        if (repair_blocked)
        {
            ASSERT_EQ(1u, consumer->m_toSync.count(key));
            EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_),
                      RouteNextHop("10.64.0.0/24"));
            if (neighbor_present)
            {
                EXPECT_EQ(0u, gNeighOrch->m_syncdNextHops.count(Key(moving_ip)));
            }
            if (check_multipath)
            {
                EXPECT_EQ(gNeighOrch->getLocalNextHopId(Key("192.168.1.2")), RouteNextHop(multipath));
            }
            EXPECT_FALSE(incarnation->retired);
            for (const auto& ctx : m_MuxCable->nbr_handler_->neighbor_contexts_)
            {
                if (ctx.neighborEntry == Key(moving_ip))
                {
                    EXPECT_TRUE(neighbor_present ? ctx.neighbor_created : ctx.nexthop_created);
                }
            }
            EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
            EXPECT_EQ(refs, RifRefs());
            static_cast<Orch*>(gNeighOrch)->doTask();
            EXPECT_EQ(1u, consumer->m_toSync.count(key));
            EXPECT_EQ(0, created);
            EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_),
                      RouteNextHop("10.64.0.0/24"));
            repair_blocked = false;
            static_cast<Orch*>(gNeighOrch)->doTask();
        }
        ASSERT_EQ(0u, consumer->m_toSync.count(key));
        ASSERT_EQ(1, created);
        auto local = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, local);
        if (!neighbor_present)
        {
            EXPECT_EQ(original, local);
        }
        ExpectNeighborHardware(moving_ip, true);
        EXPECT_EQ(local, m_MuxOrch->getMuxCable("Ethernet8")->getNextHopId(Key(moving_ip)));
        EXPECT_EQ(local, RouteNextHop("10.64.0.0/24"));
        if (check_multipath)
        {
            EXPECT_EQ(local, RouteNextHop(multipath));
        }
        EXPECT_EQ(refs + 1, RifRefs());
        auto crm = CrmUsed();
        cleanup_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(local, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
    }

    INSTANTIATE_TEST_SUITE_P(IndependentObjects, MuxNativeReceiverTest,
        testing::Combine(testing::Bool(), testing::Bool()));

    TEST_F(MuxAssociationTest, QueuedReceiverRepairDoesNotReviveStandbyObligation)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(false, cleanup_blocked));
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry)
            .WillOnce(Return(SAI_STATUS_FAILURE));
        SetFdb(moving_mac, "Ethernet8");
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        SetMuxStateFromAppDb(STANDBY_STATE, "Ethernet8");
        ASSERT_EQ(STANDBY_STATE, m_MuxOrch->getMuxCable("Ethernet8")->getState());
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        ExpectNeighborHardware(moving_ip, false);
        cleanup_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
    }

    TEST_F(MuxAssociationTest, ReceiverRepairNeverReplacesPendingDelete)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(false, cleanup_blocked));
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, vector<FieldValueTuple>{}));
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry).WillOnce(Return(SAI_STATUS_FAILURE));
        SetFdb(moving_mac, "Ethernet8");
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        EXPECT_EQ(DEL_COMMAND, kfvOp(consumer->m_toSync.find(key)->second));
        cleanup_blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(Key(moving_ip)));
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        static_cast<Orch*>(gNeighOrch)->doTask();
        RecoveryTimerTick();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_EQ(0u, gNeighOrch->getNeighborTable().count(Key(moving_ip)));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        ExpectNeighborHardware(moving_ip, false);
    }

    TEST_F(MuxAssociationTest, NativeSuccessWithoutObjectCannotCompleteQueuedRepair)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(true, cleanup_blocked, true));
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
            .WillOnce(Return(SAI_STATUS_ITEM_ALREADY_EXISTS))
            .WillOnce(Return(SAI_STATUS_ITEM_ALREADY_EXISTS))
            .WillRepeatedly([](sai_object_id_t* oid, sai_object_id_t sw, uint32_t count,
                               const sai_attribute_t* attrs) -> sai_status_t {
                return old_sai_next_hop_api->create_next_hop(oid, sw, count, attrs);
            });
        SetFdb(moving_mac, "Ethernet8");
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(1u, consumer->m_toSync.count(key));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        EXPECT_EQ(0u, gNeighOrch->m_syncdNextHops.count(Key(moving_ip)));
        EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_),
                  RouteNextHop("10.64.0.0/24"));
        EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_NE(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        cleanup_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
    }

    TEST_F(MuxAssociationTest, ActiveFdbReceiverPermanentlyAdoptsOwnedObjects)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseTransfer(true, false, false, true));
    }

    TEST_F(MuxAssociationTest, ReceiverRepairNeverReplacesNewerMacSet)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(false, cleanup_blocked));
        const string newer_mac = "62:f9:65:10:2f:69";
        SetFdb(newer_mac, "Ethernet8");
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation;
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND,
            vector<FieldValueTuple>{{"neigh", newer_mac}, {"family", "IPv4"}}));
        bool blocked = true;
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry)
            .WillRepeatedly([&](const sai_neighbor_entry_t* entry, uint32_t count,
                                const sai_attribute_t* attrs) -> sai_status_t {
                return blocked ? SAI_STATUS_FAILURE : old_sai_neighbor_api->create_neighbor_entry(entry, count, attrs);
            });
        SetFdb(moving_mac, "Ethernet8");
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        const auto& fields = kfvFieldsValues(consumer->m_toSync.find(key)->second);
        EXPECT_NE(fields.end(), find(fields.begin(), fields.end(), FieldValueTuple("neigh", newer_mac)));
        auto original = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_EQ(MacAddress(newer_mac), gNeighOrch->getNeighborTable().at(Key(moving_ip)).mac);
        EXPECT_TRUE(incarnation->retired);
        EXPECT_NE(incarnation, gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation);
        EXPECT_EQ(original, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        cleanup_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        ExpectNeighborHardware(moving_ip, true);
        auto entry = SaiNeighbor(moving_ip);
        sai_attribute_t attr{};
        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_neighbor_api->get_neighbor_entry_attribute(&entry, 1, &attr));
        EXPECT_EQ(MacAddress(newer_mac), MacAddress(attr.value.mac));
    }

    TEST_F(MuxAssociationTest, ReceiverRepairPreservesPendingDeleteThenSetSequence)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(false, cleanup_blocked));
        const string newer_mac = "62:f9:65:10:2f:69";
        SetFdb(newer_mac, "Ethernet8");
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + moving_ip;
        vector<KeyOpFieldsValuesTuple> expected{
            KeyOpFieldsValuesTuple(key, DEL_COMMAND, vector<FieldValueTuple>{}),
            KeyOpFieldsValuesTuple(key, SET_COMMAND,
                vector<FieldValueTuple>{{"neigh", newer_mac}, {"family", "IPv4"}})
        };
        for (const auto& update : expected)
            consumer->addToSync(update);
        bool blocked = true;
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        EXPECT_CALL(*mock_sai_neighbor_api, create_neighbor_entry)
            .WillRepeatedly([&](const sai_neighbor_entry_t* entry, uint32_t count,
                                const sai_attribute_t* attrs) -> sai_status_t {
                return blocked ? SAI_STATUS_FAILURE : old_sai_neighbor_api->create_neighbor_entry(entry, count, attrs);
            });
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation;
        auto original = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        SetFdb(moving_mac, "Ethernet8");
        vector<KeyOpFieldsValuesTuple> queued;
        auto range = consumer->m_toSync.equal_range(key);
        for (auto it = range.first; it != range.second; ++it)
            queued.push_back(it->second);
        EXPECT_EQ(expected, queued);
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop(original))
            .WillOnce(Return(SAI_STATUS_FAILURE));
        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_TRUE(incarnation->retired);
        EXPECT_NE(incarnation, gNeighOrch->getNeighborTable().at(Key(moving_ip)).incarnation);
        EXPECT_EQ(original, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        EXPECT_EQ(MacAddress(newer_mac), gNeighOrch->getNeighborTable().at(Key(moving_ip)).mac);
        auto entry = SaiNeighbor(moving_ip);
        sai_attribute_t attr{};
        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_neighbor_api->get_neighbor_entry_attribute(&entry, 1, &attr));
        EXPECT_EQ(MacAddress(newer_mac), MacAddress(attr.value.mac));
        cleanup_blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        ExpectNeighborHardware(moving_ip, true);
    }

    class MuxFdbRouteRetryTest : public MuxAssociationTest, public testing::WithParamInterface<bool> {};

    TEST_P(MuxFdbRouteRetryTest, FdbMoveRetriesOnlyUnacknowledgedRouteAndReferenceChanges)
    {
        const bool receiver_active = GetParam();
        SetMuxStateFromAppDb(receiver_active ? ACTIVE_STATE : STANDBY_STATE, "Ethernet8");
        SetAndAssertMuxState(receiver_active ? STANDBY_STATE : ACTIVE_STATE);
        SetFdb(moving_mac, TEST_INTERFACE);
        NeighborEvent(moving_ip, true, moving_mac);
        AddRoute("10.85.0.0/24", moving_ip);
        AddRoute("10.86.0.0/24", moving_ip);
        const auto original = RouteNextHop("10.86.0.0/24");
        const auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        bool blocked = true;
        int failed_route_attempts = 0, host_creates = 0;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (sai_serialize_ip_prefix(entry->destination) == "10.86.0.0/24")
            {
                ++failed_route_attempts;
                if (blocked)
                    return SAI_STATUS_FAILURE;
            }
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_CALL(*mock_sai_route_api, create_route_entry)
            .WillRepeatedly([&](const sai_route_entry_t* entry, uint32_t count,
                               const sai_attribute_t* attrs) -> sai_status_t {
                if (sai_serialize_ip_prefix(entry->destination) == moving_ip + "/32")
                    ++host_creates;
                return old_sai_route_api->create_route_entry(entry, count, attrs);
            });
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
            .Times(receiver_active ? 1 : 0)
            .WillRepeatedly(testing::Invoke(old_sai_next_hop_api->create_next_hop));
        SetFdb(moving_mac, "Ethernet8");
        auto receiver = m_MuxOrch->getMuxCable("Ethernet8");
        const auto local = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, local);
        ASSERT_TRUE(gNeighOrch->isHwConfigured(Key(moving_ip)));
        EXPECT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
        EXPECT_FALSE(receiver->isStateChangeFailed());
        EXPECT_EQ(receiver_active ? local : tunnel, RouteNextHop("10.85.0.0/24"));
        EXPECT_EQ(original, RouteNextHop("10.86.0.0/24"));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        auto neighbors = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        const string key = VLAN_1000 + ":" + moving_ip;
        ASSERT_EQ(1u, neighbors->m_toSync.count(key));
        const auto queued = neighbors->m_toSync.find(key)->second;
        const auto baseline = CrmUsed();
        const auto refs = RifRefs();
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            static_cast<Orch*>(gNeighOrch)->doTask();
            ASSERT_EQ(1u, neighbors->m_toSync.count(key));
            EXPECT_EQ(queued, neighbors->m_toSync.find(key)->second);
            EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
            EXPECT_EQ(baseline, CrmUsed());
            EXPECT_EQ(refs, RifRefs());
        }
        EXPECT_GT(failed_route_attempts, 2);
        EXPECT_EQ(receiver_active ? 0 : 1, host_creates);
        auto routes = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
        if (!receiver_active)
        {
            ConfigureFg("10.87.0.0/24", moving_ip);
            routes->addToSync(KeyOpFieldsValuesTuple("10.87.0.0/24", SET_COMMAND,
                vector<FieldValueTuple>{{"nexthop", moving_ip}, {"ifname", VLAN_1000}}));
            static_cast<Orch*>(gRouteOrch)->doTask();
            EXPECT_EQ(1u, routes->m_toSync.count("10.87.0.0/24"));
            EXPECT_FALSE(gFgNhgOrch->syncdContainsFgNhg(gVirtualRouterId, IpPrefix("10.87.0.0/24")));
            EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        }
        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, neighbors->m_toSync.count(key));
        EXPECT_EQ(receiver_active ? local : tunnel, RouteNextHop("10.86.0.0/24"));
        EXPECT_EQ(receiver_active ? local : SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        EXPECT_EQ(receiver_active, gNeighOrch->isHwConfigured(Key(moving_ip)));
        if (receiver_active)
        {
            EXPECT_EQ(2, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
            EXPECT_EQ(baseline, CrmUsed());
            EXPECT_EQ(refs, RifRefs());
        }
        else
        {
            static_cast<Orch*>(gRouteOrch)->doTask();
            ASSERT_EQ(0u, routes->m_toSync.count("10.87.0.0/24"));
            ExpectFgNextHop("10.87.0.0/24", tunnel);
            EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
            DeleteRoute("10.87.0.0/24");
        }
        EXPECT_EQ(receiver_active ? 0 : 1, host_creates);
        DeleteRoute("10.85.0.0/24");
        DeleteRoute("10.86.0.0/24");
    }

    INSTANTIATE_TEST_SUITE_P(ReceiverRole, MuxFdbRouteRetryTest, testing::Bool());

    TEST_F(MuxAssociationTest, FdbReceiverAdoptsPrimariesBeforeRouteRepairCompletes)
    {
        SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
        bool cleanup_blocked = true;
        int removals = 0;
        ASSERT_NO_FATAL_FAILURE(HoldOwnedHop(cleanup_blocked, removals));
        const auto retained = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, retained);
        const auto tunnel = m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        bool route_blocked = true;
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (route_blocked && sai_serialize_ip_prefix(entry->destination) == "10.40.0.0/24" &&
                attr->value.oid != tunnel)
                return SAI_STATUS_FAILURE;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        SetFdb(moving_mac, "Ethernet8");
        EXPECT_EQ(retained, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        EXPECT_TRUE(gNeighOrch->isHwConfigured(Key(moving_ip)));
        EXPECT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
        EXPECT_FALSE(m_MuxOrch->hasPendingNextHopRecovery(Key(moving_ip)));
        EXPECT_EQ(tunnel, RouteNextHop("10.40.0.0/24"));
        auto neighbors = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        const string key = VLAN_1000 + ":" + moving_ip;
        ASSERT_EQ(1u, neighbors->m_toSync.count(key));
        const auto attempts = removals;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(attempts, removals);
        EXPECT_EQ(retained, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        route_blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, neighbors->m_toSync.count(key));
        EXPECT_EQ(retained, RouteNextHop("10.40.0.0/24"));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        DeleteRoute("10.40.0.0/24");
    }

    TEST_F(MuxAssociationTest, BfdNeverBindsAnIndependentNextHopWithoutNeighborHardware)
    {
        bool cleanup_blocked = true;
        ASSERT_NO_FATAL_FAILURE(HoldIndependentFailure(false, cleanup_blocked));
        auto oid = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, oid);
        ASSERT_FALSE(gNeighOrch->isHwConfigured(Key(moving_ip)));
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(VLAN_1000, moving_ip));
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        NeighborEvent(moving_ip, true, moving_mac);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        auto key = VLAN_1000 + ":" + moving_ip;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, DEL_COMMAND, {}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        cleanup_blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(key));
        ExpectRemovedNextHop(oid);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        RecoveryDue();
        DispatchMux();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
    }

    TEST_P(MuxVoqSystemTest, SystemSetKeepsCanonicalBfdRepairAheadOfDeleteCancellation)
    {
        SystemEvent(true);
        auto consumer = gNeighOrch->getConsumerBase(CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME);
        ASSERT_EQ(0u, consumer->m_toSync.count(SystemKey()));
        NeighborEntry neighbor(IpAddress(ip), remote);
        const auto oid = gNeighOrch->getLocalNextHopId(Key(ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, oid);
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(neighbor));
        BfdSessions bfd;
        bfd.Start(m_app_db.get(), m_state_db.get());
        ASSERT_NO_FATAL_FAILURE(bfd.Add(remote, ip));
        bfd.ExpectBinding(0, oid);
        const auto crm = CrmUsed();
        const auto inband_refs = RifRefs();
        const auto remote_refs = gIntfsOrch->m_syncdIntfses.at(remote).ref_count;
        bool blocked = true;
        bfd_set = [&](sai_object_id_t session, const sai_attribute_t* attr) -> sai_status_t {
            return blocked && attr->value.oid == oid ? SAI_STATUS_FAILURE
                : old_sai_bfd_api->set_bfd_session_attribute(session, attr);
        };
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hop).WillRepeatedly(Return(SAI_STATUS_FAILURE));
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        SystemEvent(false);
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        const uint32_t encap = GetParam() ? 43 : 42;
        SystemEvent(true, encap);
        ASSERT_EQ(2u, consumer->m_toSync.count(SystemKey()));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(2u, consumer->m_toSync.count(SystemKey()));
        auto entry = consumer->m_toSync.equal_range(SystemKey()).first;
        EXPECT_EQ(DEL_COMMAND, kfvOp(entry->second));
        ++entry;
        EXPECT_EQ(SET_COMMAND, kfvOp(entry->second));
        EXPECT_EQ((vector<FieldValueTuple>{{"neigh", mac}, {"encap_index", to_string(encap)}}),
                  kfvFieldsValues(entry->second));
        bfd.ExpectBinding(0, SAI_NULL_OBJECT_ID);
        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(0u, consumer->m_toSync.count(SystemKey()));
        bfd.ExpectBinding(0, oid);
        EXPECT_EQ(encap, gNeighOrch->getNeighborTable().at(neighbor).voq_encap_index);
        EXPECT_EQ(remote_refs, gIntfsOrch->m_syncdIntfses.at(remote).ref_count);
        EXPECT_EQ(inband_refs, RifRefs());
        EXPECT_EQ(crm, CrmUsed());
    }

    TEST_P(MuxVoqSystemTest, SystemConsumerRepairsCanonicalNextHopBeforeCompletingSet)
    {
        bool fail_next_create = false;
        int calls = 0, creates = 0;
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
            .WillRepeatedly([&](sai_object_id_t* oid, sai_object_id_t sw, uint32_t count,
                                const sai_attribute_t* attrs) -> sai_status_t {
                ++calls;
                if (fail_next_create)
                {
                    fail_next_create = false;
                    return SAI_STATUS_TABLE_FULL;
                }
                auto status = old_sai_next_hop_api->create_next_hop(oid, sw, count, attrs);
                if (status == SAI_STATUS_SUCCESS)
                    ++creates;
                return status;
            });
        auto baseline = CrmUsed();
        int inband_refs = RifRefs();
        SystemEvent(true);
        auto consumer = gNeighOrch->getConsumerBase(CHASSIS_APP_SYSTEM_NEIGH_TABLE_NAME);
        ASSERT_EQ(0u, consumer->m_toSync.count(SystemKey()));
        NeighborEntry neighbor(IpAddress(ip), remote);
        ASSERT_EQ(42u, gNeighOrch->getNeighborTable().at(neighbor).voq_encap_index);
        auto programmed = CrmUsed();
        bool block_delete = true;
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
            .WillRepeatedly([&](const sai_neighbor_entry_t* entry) -> sai_status_t {
                return block_delete ? SAI_STATUS_FAILURE : old_sai_neighbor_api->remove_neighbor_entry(entry);
            });
        SystemEvent(false);
        ASSERT_EQ(1u, consumer->m_toSync.count(SystemKey()));
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(ip)));
        ASSERT_TRUE(gNeighOrch->isHwConfigured(neighbor));
        EXPECT_EQ(1, gIntfsOrch->m_syncdIntfses.at(remote).ref_count);
        uint32_t encap = GetParam() ? 43 : 42;
        fail_next_create = true;
        SystemEvent(true, encap);
        EXPECT_EQ(2u, consumer->m_toSync.count(SystemKey()));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(ip)));
        EXPECT_EQ(1, creates);
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(SystemKey()));
        EXPECT_EQ(3, calls);
        EXPECT_EQ(2, creates);
        EXPECT_NE(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(ip)));
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(neighbor));
        EXPECT_EQ(encap, gNeighOrch->getNeighborTable().at(neighbor).voq_encap_index);
        EXPECT_EQ(2, gIntfsOrch->m_syncdIntfses.at(remote).ref_count);
        EXPECT_EQ(inband_refs, RifRefs());
        EXPECT_EQ(programmed, CrmUsed());
        block_delete = false;
        SystemEvent(false);
        EXPECT_EQ(0u, consumer->m_toSync.count(SystemKey()));
        EXPECT_EQ(baseline, CrmUsed());
    }

    INSTANTIATE_TEST_SUITE_P(SystemEncapsulation, MuxVoqSystemTest, testing::Bool());

    TEST_P(MuxPrefixMacTest, IncomingMacRoleChangeKeepsPrefixFailureRetryable)
    {
        const string ip = "192.168.2.4";
        const string old_mac = "62:f9:65:10:2f:70";
        const string new_mac = "62:f9:65:10:2f:71";
        SetMuxStateFromAppDb(GetParam() ? ACTIVE_STATE : STANDBY_STATE);
        SetMuxStateFromAppDb(GetParam() ? STANDBY_STATE : ACTIVE_STATE, "Ethernet8");
        SetFdb(old_mac, TEST_INTERFACE);
        SetFdb(new_mac, "Ethernet8");
        NeighborEvent(ip, true, old_mac);
        ASSERT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(ip)));
        auto old_target = RouteNextHop(ip);
        auto local = gNeighOrch->getLocalNextHopId(Key(ip));
        auto target = GetParam() ? m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_) : local;
        ASSERT_NE(old_target, target);
        bool blocked = true;
        route_set = [&, target](const sai_route_entry_t* entry, const sai_attribute_t* attr) -> sai_status_t {
            if (sai_serialize_ip_prefix(entry->destination) == ip + "/32" &&
                attr->id == SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID && attr->value.oid == target && blocked)
                return SAI_STATUS_FAILURE;
            return old_sai_route_api->set_route_entry_attribute(entry, attr);
        };
        EXPECT_CALL(*mock_sai_route_api, create_route_entry).Times(0);
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop).Times(0);
        auto crm = CrmUsed();
        int refs = RifRefs();
        auto consumer = gNeighOrch->getConsumerBase(APP_NEIGH_TABLE_NAME);
        string key = VLAN_1000 + ":" + ip;
        consumer->addToSync(KeyOpFieldsValuesTuple(key, SET_COMMAND,
            vector<FieldValueTuple>{{"neigh", new_mac}, {"family", "IPv4"}}));
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(1u, consumer->m_toSync.count(key));
        EXPECT_EQ(old_target, RouteNextHop(ip));
        EXPECT_EQ(TEST_INTERFACE, m_MuxOrch->getNexthopMuxName(Key(ip)));
        EXPECT_TRUE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_pending);
        EXPECT_TRUE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_owned);
        EXPECT_TRUE(m_MuxOrch->hasPendingNextHopRecovery(Key(ip)));
        static_cast<Orch*>(gNeighOrch)->doTask();
        EXPECT_EQ(1u, consumer->m_toSync.count(key));
        EXPECT_EQ(old_target, RouteNextHop(ip));
        blocked = false;
        static_cast<Orch*>(gNeighOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(key));
        EXPECT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key(ip)));
        EXPECT_EQ(target, RouteNextHop(ip));
        EXPECT_FALSE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_pending);
        EXPECT_EQ(local, gNeighOrch->getLocalNextHopId(Key(ip)));
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(refs, RifRefs());
        NeighborEvent(ip, false);
    }

    INSTANTIATE_TEST_SUITE_P(MacRoleDirections, MuxPrefixMacTest, testing::Bool());

    TEST_F(MuxPrefixRecoveryTest, InitPrefixBootstrapDoesNotRequireTunnel)
    {
        const string ip = "192.168.0.3";
        auto old_state = m_MuxCable->state_;
        auto tunnels = m_MuxOrch->mux_tunnel_nh_;
        bool restored = false;
        auto restore = shared_ptr<void>(nullptr, [&](void*) {
            if (!restored)
            {
                m_MuxCable->state_ = old_state;
                m_MuxOrch->mux_tunnel_nh_ = tunnels;
                m_MuxOrch->updateCachedNeighbors();
                m_MuxOrch->disableCachingNeighborUpdate();
            }
        });
        m_MuxCable->state_ = MuxState::MUX_STATE_INIT;
        m_MuxOrch->mux_tunnel_nh_.clear();
        m_MuxOrch->enableCachingNeighborUpdate();
        NeighborEvent(ip);
        ASSERT_FALSE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_pending);
        auto local = gNeighOrch->getLocalNextHopId(Key(ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, local);
        EXPECT_EQ(local, RouteNextHop(ip));
        auto route = SaiRoute(ip);
        sai_attribute_t attr{};
        attr.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
        ASSERT_EQ(SAI_STATUS_SUCCESS, old_sai_route_api->get_route_entry_attribute(&route, 1, &attr));
        EXPECT_EQ(SAI_PACKET_ACTION_DROP, attr.value.s32);
        m_MuxCable->state_ = old_state;
        m_MuxOrch->mux_tunnel_nh_ = tunnels;
        m_MuxOrch->updateCachedNeighbors();
        m_MuxOrch->disableCachingNeighborUpdate();
        restored = true;
        EXPECT_EQ(m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_), RouteNextHop(ip));
        ASSERT_TRUE(m_MuxCable->nbr_handler_->prepareStateChange(true));
        m_MuxCable->nbr_handler_->commitStateChange();
    }

    TEST_F(MuxAssociationTest, FdbAbaCannotReviveReleasedCleanupOwnership)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseTransfer(true, true, false));
    }

    TEST_F(MuxAssociationTest, StandbyFdbReceiverLeavesUnadoptedObjectsForCleanup)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseTransfer(false, false, false));
    }

    TEST_F(MuxAssociationTest, LaterReceiverActivationAdoptsBeforeOldTimerCleanup)
    {
        ASSERT_NO_FATAL_FAILURE(ExerciseTransfer(false, false, true));
    }

    TEST_F(MuxAssociationTest, FdbTransferRetiresOldActiveNeighborRestoration)
    {
        SetFdb(moving_mac, TEST_INTERFACE);
        NeighborEvent(moving_ip, true, moving_mac);
        SetAndAssertMuxState(ACTIVE_STATE);
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        SetFdb(moving_mac, "Ethernet8");
        ASSERT_EQ("Ethernet8", m_MuxOrch->getNexthopMuxName(Key(moving_ip)));
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        EXPECT_EQ(STANDBY_STATE, m_MuxOrch->getMuxCable("Ethernet8")->getState());
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        ExpectNeighborHardware(moving_ip, false);
    }

    TEST_F(MuxAssociationTest, ReceiverRecreationRetiresConfirmedOldNextHopRemoval)
    {
        bool blocked = true;
        int removals = 0;
        ASSERT_NO_FATAL_FAILURE(HoldOwnedHop(blocked, removals));
        EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entry)
            .WillOnce(Return(SAI_STATUS_FAILURE));
        blocked = false;
        SetFdb(moving_mac, "Ethernet8");
        ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        for (const auto& ctx : m_MuxCable->nbr_handler_->neighbor_contexts_)
        {
            if (ctx.neighborEntry == Key(moving_ip))
            {
                EXPECT_FALSE(ctx.nexthop_created);
            }
        }
        SetMuxStateFromAppDb(ACTIVE_STATE, "Ethernet8");
        auto replacement = gNeighOrch->getLocalNextHopId(Key(moving_ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, replacement);
        auto crm = CrmUsed();
        int refs = RifRefs();
        int prior_removals = removals;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        EXPECT_EQ(prior_removals, removals);
        EXPECT_EQ(replacement, gNeighOrch->getLocalNextHopId(Key(moving_ip)));
        EXPECT_EQ(replacement, RouteNextHop("10.40.0.0/24"));
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(moving_ip)));
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(refs, RifRefs());
    }

    TEST_F(MuxHybridTest, RemoteSystemPortRepairUsesCanonicalInbandKey)
    {
        const string remote = "remote-system-port";
        const string ip = "192.168.6.3";
        Port port;
        ASSERT_TRUE(gPortsOrch->getPort(VLAN_1000, port));
        ASSERT_EQ(0u, gPortsOrch->m_portList.count(remote));
        auto previous_switch = gMySwitchType;
        auto previous_inband = gPortsOrch->m_inbandPortName;
        auto previous_table = std::move(gNeighOrch->m_tableVoqSystemNeighTable);
        NeighborEntry key(IpAddress(ip), remote);
        auto cleanup = shared_ptr<void>(nullptr, [&](void*) {
            NeighborContext ctx(key);
            gNeighOrch->removeNeighbor(ctx);
            gPortsOrch->m_portList.erase(remote);
            gIntfsOrch->m_syncdIntfses.erase(remote);
            gPortsOrch->m_inbandPortName = previous_inband;
            gMySwitchType = previous_switch;
            gNeighOrch->m_tableVoqSystemNeighTable = std::move(previous_table);
        });
        port.m_alias = remote;
        port.m_type = Port::SYSTEM;
        port.m_system_port_info.type = SAI_SYSTEM_PORT_TYPE_REMOTE;
        gPortsOrch->setPort(remote, port);
        gPortsOrch->m_inbandPortName = VLAN_1000;
        gIntfsOrch->m_syncdIntfses[remote] = gIntfsOrch->m_syncdIntfses.at(VLAN_1000);
        gIntfsOrch->m_syncdIntfses.at(remote).ref_count = 0;
        gMySwitchType = "voq";
        gNeighOrch->m_tableVoqSystemNeighTable = make_unique<Table>(m_app_db.get(), "MUX_UT_SYSTEM_NEIGH");
        auto& table = *gNeighOrch->m_tableVoqSystemNeighTable;
        table.set(remote + table.getTableNameSeparator() + ip, {{"encap_index", "42"}});
        auto before = CrmUsed();
        int local_refs = RifRefs();
        EXPECT_CALL(*mock_sai_next_hop_api, create_next_hop)
            .Times(1)
            .WillOnce([](sai_object_id_t* oid, sai_object_id_t switch_id, uint32_t count,
                         const sai_attribute_t* attrs) -> sai_status_t {
                return old_sai_next_hop_api->create_next_hop(oid, switch_id, count, attrs);
            });
        NeighborContext ctx(key);
        ctx.mac = MacAddress("62:f9:65:10:2f:68");
        ASSERT_TRUE(gNeighOrch->addNeighbor(ctx));
        auto oid = gNeighOrch->getLocalNextHopId(Key(ip));
        ASSERT_NE(SAI_NULL_OBJECT_ID, oid);
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(key));
        EXPECT_EQ(2, gIntfsOrch->m_syncdIntfses.at(remote).ref_count);
        auto incarnation = gNeighOrch->getNeighborTable().at(key).incarnation;
        auto programmed = CrmUsed();
        ASSERT_TRUE(gNeighOrch->addNeighbor(ctx));
        EXPECT_EQ(incarnation, gNeighOrch->getNeighborTable().at(key).incarnation);
        EXPECT_EQ(oid, gNeighOrch->getLocalNextHopId(Key(ip)));
        EXPECT_EQ(programmed, CrmUsed());
        EXPECT_EQ(local_refs, RifRefs());
        ASSERT_TRUE(gNeighOrch->removeNeighbor(ctx));
        EXPECT_EQ(0, gIntfsOrch->m_syncdIntfses.at(remote).ref_count);
        EXPECT_EQ(before, CrmUsed());
    }

    TEST_P(MuxConversionTest, ConvertedPrefixOwnsRouteAcrossMacUpdateAndDelete)
    {
        const string port = "Ethernet8";
        const string ip = "192.168.2.3";
        const string mac = "62:f9:65:10:2f:67";
        const string replacement_mac = "62:f9:65:10:2f:68";
        bool config_conversion = get<1>(GetParam());
        if (config_conversion)
        {
            MuxConfig(port, false, "prefix-route");
            ASSERT_FALSE(m_MuxOrch->isMuxExists(port));
        }
        else
        {
            SetMuxStateFromAppDb(get<0>(GetParam()), port);
        }
        NeighborEvent(ip, true, mac);
        ASSERT_FALSE(gNeighOrch->isPrefixNeighbor(Key(ip)));
        if (config_conversion)
        {
            SetFdb(mac, port);
            MuxConfig(port, true, "prefix-route");
            SetMuxStateFromAppDb(get<0>(GetParam()), port);
        }
        else
        {
            SetFdb(mac, port);
        }
        ASSERT_TRUE(gNeighOrch->isPrefixNeighbor(Key(ip)));
        ASSERT_TRUE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_owned);
        auto target = get<0>(GetParam()) == ACTIVE_STATE ? gNeighOrch->getLocalNextHopId(Key(ip))
            : m_MuxOrch->getNextHopTunnelId(MUX_TUNNEL, m_MuxCable->peer_ip4_);
        EXPECT_EQ(target, RouteNextHop(ip));
        SetFdb(replacement_mac, port);
        auto crm = CrmUsed();
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_route_api, create_route_entry).Times(0);
        NeighborEvent(ip, true, replacement_mac);
        EXPECT_EQ(target, RouteNextHop(ip));
        EXPECT_EQ(crm, CrmUsed());
        EXPECT_EQ(refs, RifRefs());
        EXPECT_FALSE(gNeighOrch->getNeighborTable().at(Key(ip)).incarnation->prefix_pending);
        auto incarnation = gNeighOrch->getNeighborTable().at(Key(ip)).incarnation;
        NeighborEvent(ip, false);
        EXPECT_TRUE(incarnation->retired);
        EXPECT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(ip)));
        EXPECT_EQ(refs - 2, RifRefs());
        auto route = SaiRoute(ip);
        sai_attribute_t attr{};
        attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
        EXPECT_EQ(SAI_STATUS_ITEM_NOT_FOUND, old_sai_route_api->get_route_entry_attribute(&route, 1, &attr));
    }

    INSTANTIATE_TEST_SUITE_P(AssociationConversions, MuxConversionTest,
        testing::Combine(testing::Values(ACTIVE_STATE, STANDBY_STATE), testing::Bool()));

    TEST_P(MuxTransitionModesTest, NewFgRouteDefersUntilActiveRecoveryCompletes)
    {
        const string prefix = "10.41.0.0/24";
        SetAndAssertMuxState(ACTIVE_STATE);
        ConfigureFg(prefix);
        bool blocked = true;
        int attempts = 0;
        ASSERT_NO_FATAL_FAILURE(HoldActiveNeighborRecovery(blocked, attempts));
        if (!IsPrefixBasedMuxNeighbor())
        {
            ASSERT_EQ(SAI_NULL_OBJECT_ID, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        }
        auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
        consumer->addToSync(KeyOpFieldsValuesTuple(prefix, SET_COMMAND,
            vector<FieldValueTuple>{{"nexthop", SERVER_IP1}, {"ifname", VLAN_1000}}));
        auto crm = CrmUsed();
        static_cast<Orch*>(gRouteOrch)->doTask();
        EXPECT_EQ(1u, consumer->m_toSync.count(prefix));
        EXPECT_FALSE(gFgNhgOrch->syncdContainsFgNhg(gVirtualRouterId, IpPrefix(prefix)));
        EXPECT_EQ(crm, CrmUsed());
        blocked = false;
        ASSERT_NO_FATAL_FAILURE(CompleteRecovery());
        static_cast<Orch*>(gRouteOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(prefix));
        ASSERT_TRUE(gFgNhgOrch->syncdContainsFgNhg(gVirtualRouterId, IpPrefix(prefix)));
        auto& fg = gFgNhgOrch->m_syncdFGRouteTables.at(gVirtualRouterId).at(IpPrefix(prefix));
        ASSERT_FALSE(fg.nhopgroup_members.empty());
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        for (auto member : fg.nhopgroup_members)
        {
            sai_attribute_t attr{};
            attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
            ASSERT_EQ(SAI_STATUS_SUCCESS,
                      old_sai_next_hop_group_api->get_next_hop_group_member_attribute(member, 1, &attr));
            EXPECT_EQ(local, attr.value.oid);
        }
        EXPECT_EQ(1, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
        DeleteRoute(prefix);
        EXPECT_EQ(0, gNeighOrch->getNextHopRefCount(Key(SERVER_IP1)));
    }

    TEST_F(MuxHybridTest, ConfigurationDeletionWaitsForOwnedCleanupBeforeRecreation)
    {
        bool blocked = true;
        int creates = 0;
        int removals = 0;
        HoldFirstEnableCleanup(blocked, creates, removals);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_TRUE(m_MuxCable->isStateChangeFailed());
        m_MuxCable->recovery_retry_at_ = std::chrono::steady_clock::now() + std::chrono::hours(1);
        SetMuxStateFromAppDb(STANDBY_STATE);
        auto old = m_MuxCable;
        MuxConfig(TEST_INTERFACE, false);
        auto consumer = m_MuxOrch->getConsumerBase(CFG_MUX_CABLE_TABLE_NAME);
        ASSERT_EQ(1u, consumer->m_toSync.count(TEST_INTERFACE));
        EXPECT_EQ(old, m_MuxOrch->getMuxCable(TEST_INTERFACE));
        MuxConfig(TEST_INTERFACE, true);
        EXPECT_EQ(2u, consumer->m_toSync.count(TEST_INTERFACE));
        EXPECT_EQ(old, m_MuxOrch->getMuxCable(TEST_INTERFACE));
        int attempts = removals;
        static_cast<Orch*>(m_MuxOrch)->doTask();
        EXPECT_EQ(attempts, removals);
        blocked = false;
        RecoveryDue();
        RecoveryTimerTick();
        ASSERT_FALSE(old->isStateChangeFailed());
        EXPECT_TRUE(old->nbr_handler_->neighbor_contexts_.empty());
        ExpectNeighborHardware(SERVER_IP1, false);
        static_cast<Orch*>(m_MuxOrch)->doTask();
        ASSERT_EQ(0u, consumer->m_toSync.count(TEST_INTERFACE));
        ASSERT_TRUE(m_MuxOrch->isMuxExists(TEST_INTERFACE));
        m_MuxCable = m_MuxOrch->getMuxCable(TEST_INTERFACE);
        EXPECT_TRUE(m_MuxCable->nbr_handler_->neighbor_contexts_.empty());
        EXPECT_TRUE(m_MuxCable->nbr_handler_->transition_.empty());
        NeighborEvent(SERVER_IP1, false);
        NeighborEvent(SERVER_IP1);
        SetMuxStateFromAppDb(ACTIVE_STATE);
        ASSERT_EQ(ACTIVE_STATE, m_MuxCable->getState());
        auto local = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        attempts = removals;
        RecoveryTimerTick();
        EXPECT_EQ(attempts, removals);
        EXPECT_EQ(local, gNeighOrch->getLocalNextHopId(Key(SERVER_IP1)));
        ExpectNeighborHardware(SERVER_IP1, true);
    }

    // Covers MuxOrch::updateFdb shared-MAC fallback: when an FDB add on a
    // mux port matches the MAC of a neighbor that bypassed mux registration
    // (e.g. learned while the FDB was aged out), the fallback loop converts
    // it. The negative-filter neighbors (different MAC, prefix_route) must
    // be skipped so unrelated NeighOrch entries are not touched.
    TEST_F(MuxRollbackTest, UpdateFdbConvertsStrandedSharedMacNeighbor)
    {
        if (IsPrefixBasedMuxNeighbor())
        {
            GTEST_SKIP() << "Fallback path is for host-route mux neighbors";
        }

        // Use a MAC distinct from the fixture's SERVER_IP1 (MAC4) so the
        // first loop's port-move branch finds no match and leaves
        // found_existing_mux_neighbor false, letting the fallback fire.
        const MacAddress shared_mac("62:f9:65:10:2f:05");
        const MacAddress other_mac("aa:bb:cc:dd:ee:ff");

        // Stranded same-MAC neighbor that the fallback should convert.
        IpAddress ip_stranded("192.168.0.3");
        NeighborEntry stranded_entry(ip_stranded, VLAN_1000);
        NextHopKey stranded_nh(ip_stranded, VLAN_1000);
        gNeighOrch->m_syncdNeighbors[stranded_entry] =
            { shared_mac, /*hw_configured*/ false, 0, /*prefix_route*/ false };

        // Different-MAC neighbor — must hit the mac-mismatch continue.
        IpAddress ip_other_mac("192.168.0.4");
        NeighborEntry other_mac_entry(ip_other_mac, VLAN_1000);
        NextHopKey other_mac_nh(ip_other_mac, VLAN_1000);
        gNeighOrch->m_syncdNeighbors[other_mac_entry] =
            { other_mac, false, 0, false };

        // Prefix-route same-MAC neighbor — must hit the prefix_route continue.
        IpAddress ip_prefix("192.168.0.5");
        NeighborEntry prefix_entry(ip_prefix, VLAN_1000);
        NextHopKey prefix_nh(ip_prefix, VLAN_1000);
        gNeighOrch->m_syncdNeighbors[prefix_entry] =
            { shared_mac, false, 0, /*prefix_route*/ true };

        // Pre-populate the FDB cache so getMuxPort() resolves shared_mac to
        // TEST_INTERFACE without going through SAI notifications.
        Port vlan_port, eth_port;
        ASSERT_TRUE(gPortsOrch->getVlanByVlanId(1000, vlan_port));
        ASSERT_TRUE(gPortsOrch->getPort(TEST_INTERFACE, eth_port));
        FdbEntry fdb_entry;
        fdb_entry.mac = shared_mac;
        fdb_entry.bv_id = vlan_port.m_vlan_info.vlan_oid;
        fdb_entry.port_name = TEST_INTERFACE;
        FdbData fdb_data{};
        fdb_data.bridge_port_id = eth_port.m_bridge_port_id;
        fdb_data.type = "dynamic";
        fdb_data.origin = FDB_ORIGIN_LEARN;
        gFdbOrch->m_entries[fdb_entry] = fdb_data;

        ASSERT_EQ(m_MuxOrch->mux_nexthop_tb_.find(stranded_nh),
                  m_MuxOrch->mux_nexthop_tb_.end());

        FdbUpdate update;
        update.entry = fdb_entry;
        update.add = true;
        update.type = "dynamic";
        m_MuxOrch->updateFdb(update);

        // The stranded neighbor must now be a mux nexthop on TEST_INTERFACE.
        auto it = m_MuxOrch->mux_nexthop_tb_.find(stranded_nh);
        ASSERT_NE(it, m_MuxOrch->mux_nexthop_tb_.end());
        EXPECT_EQ(TEST_INTERFACE, it->second);

        // Mac-mismatch and prefix-route neighbors must remain untouched.
        EXPECT_EQ(m_MuxOrch->mux_nexthop_tb_.find(other_mac_nh),
                  m_MuxOrch->mux_nexthop_tb_.end());
        EXPECT_EQ(m_MuxOrch->mux_nexthop_tb_.find(prefix_nh),
                  m_MuxOrch->mux_nexthop_tb_.end());

        // Clean up the entries we injected so we don't bleed into other tests.
        gNeighOrch->m_syncdNeighbors.erase(stranded_entry);
        gNeighOrch->m_syncdNeighbors.erase(other_mac_entry);
        gNeighOrch->m_syncdNeighbors.erase(prefix_entry);
        m_MuxOrch->mux_nexthop_tb_.erase(stranded_nh);
        gFdbOrch->m_entries.erase(fdb_entry);
    }

    // Delete FDB events must be a no-op for updateFdb so that mac aging does
    // not tear down mux neighbor state out from under the cable.
    TEST_F(MuxRollbackTest, UpdateFdbDeleteIsNoOp)
    {
        FdbUpdate update;
        update.entry.mac = MacAddress("62:f9:65:10:2f:04");
        update.entry.port_name = TEST_INTERFACE;
        update.add = false;

        size_t before = m_MuxOrch->mux_nexthop_tb_.size();
        m_MuxOrch->updateFdb(update);
        EXPECT_EQ(before, m_MuxOrch->mux_nexthop_tb_.size());
    }
}
