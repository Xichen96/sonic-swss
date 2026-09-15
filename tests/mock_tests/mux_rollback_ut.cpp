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

EXTERN_MOCK_FNS

namespace mux_rollback_test
{
    DEFINE_SAI_API_MOCK(neighbor);
    DEFINE_SAI_API_MOCK_SPECIFY_ENTRY_WITH_SET(route, route);
    DEFINE_SAI_GENERIC_API_MOCK(acl, acl_entry);
    DEFINE_SAI_GENERIC_API_OBJECT_BULK_MOCK(next_hop, next_hop);
    DEFINE_SAI_GENERIC_API_MOCK(next_hop_group, next_hop_group_member);
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
            m_MuxCable->nbr_handler_->gRouteBulker.create_entries = old_create_route_entries;
            m_MuxCable->nbr_handler_->gRouteBulker.remove_entries = old_remove_route_entries;
            m_MuxCable->nbr_handler_->gRouteBulker.set_entries_attribute = old_set_route_entries_attribute;
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
