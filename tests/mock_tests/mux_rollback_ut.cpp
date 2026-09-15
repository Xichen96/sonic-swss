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

    static sai_status_t SetSingleRoute(const sai_route_entry_t* entry, const sai_attribute_t* attr)
    {
        return route_set ? route_set(entry, attr)
                         : old_sai_route_api->set_route_entry_attribute(entry, attr);
    }

    class MuxRollbackTest : public MockOrchTest
    {
    protected:
        std::string m_neighbor_mode = "host-route";
        std::string m_server_prefix = SERVER_IP1 + "/32";

        void SetMuxStateFromAppDb(std::string state)
        {
            Table mux_cable_table = Table(m_app_db.get(), APP_MUX_CABLE_TABLE_NAME);
            mux_cable_table.set(TEST_INTERFACE, { { STATE, state } });
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
            port_table.set("PortConfigDone", { { "count", to_string(1) } });
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
                ASSERT_TRUE(gNeighOrch->clearNextHopFlag(Key(SERVER_IP1), NHFLAGS_IFDOWN));
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
            consumer->m_toSync[key] = KeyOpFieldsValuesTuple(key, add ? SET_COMMAND : DEL_COMMAND, fields);
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
                    ASSERT_TRUE(gNeighOrch->clearNextHopFlag(Key(ip), NHFLAGS_IFDOWN));
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
                EXPECT_EQ(SAI_STATUS_SUCCESS, status) << ip;
            else
                EXPECT_EQ(SAI_STATUS_ITEM_NOT_FOUND, status) << ip;
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
            route_set = [](const sai_route_entry_t*, const sai_attribute_t*) {
                ADD_FAILURE() << "Preflight rejection must not program routes";
                return SAI_STATUS_FAILURE;
            };
        }

        void AddRoute(const string& prefix, const string& ip)
        {
            auto consumer = gRouteOrch->getConsumerBase(APP_ROUTE_TABLE_NAME);
            vector<FieldValueTuple> fields{{"nexthop", ip}, {"ifname", VLAN_1000}};
            consumer->m_toSync[prefix] = KeyOpFieldsValuesTuple(prefix, SET_COMMAND, fields);
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
            .WillOnce([](CREATE_BULK_PARAMS(neighbor)) {
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
            .WillOnce([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) {
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
            .WillOnce([&](GENERIC_BULK_CREATE_PARAMS(next_hop)) {
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
            EXPECT_EQ(expected.at(ctx.neighborEntry.ip_address.to_string()), ctx.nexthop_status);
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
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) {
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
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) {
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
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) {
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
        EXPECT_FALSE(m_MuxCable->setState(STANDBY_STATE));
        EXPECT_FALSE(m_MuxCable->setState(ACTIVE_STATE));
        auto feedback = m_MuxStateOrch->getConsumerBase(STATE_HW_MUX_CABLE_TABLE_NAME);
        feedback->m_toSync[TEST_INTERFACE] = KeyOpFieldsValuesTuple(
            TEST_INTERFACE, SET_COMMAND, vector<FieldValueTuple>{{STATE, STANDBY_STATE}});
        static_cast<Orch*>(m_MuxStateOrch)->doTask();
        string reported;
        ASSERT_TRUE(m_MuxStateOrch->mux_state_table_.hget(TEST_INTERFACE, STATE, reported));
        EXPECT_EQ("error", reported);

        // Explicit recovery is observable; a same-state request must not hide the failed cleanup.
        testing::Mock::VerifyAndClearExpectations(mock_sai_neighbor_api);
        m_MuxCable->rollbackStateChange();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        ExpectNeighborHardware(SERVER_IP1, false);
    }

    TEST_F(MuxHybridTest, RemovedNeighborRetainsItsNextHopWhenNextHopRemovalFails)
    {
        SetAndAssertMuxState(ACTIVE_STATE);
        auto old_oid = gNeighOrch->getLocalNextHopId(Key(SERVER_IP1));
        int refs = RifRefs();
        EXPECT_CALL(*mock_sai_next_hop_api, remove_next_hops)
            .WillOnce([](GENERIC_BULK_REMOVE_PARAMS(next_hop)) {
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
            .WillOnce([](GENERIC_BULK_CREATE_PARAMS(next_hop)) {
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
        testing::Mock::VerifyAndClearExpectations(mock_sai_acl_api);
        m_MuxCable->rollbackStateChange();
        EXPECT_FALSE(m_MuxCable->isStateChangeFailed());
        EXPECT_NE(nullptr, m_MuxCable->acl_handler_);
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
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) {
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
            .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) {
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
            .WillOnce([&](GENERIC_BULK_REMOVE_PARAMS(next_hop)) {
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
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) {
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
                EXPECT_EQ(old.second.next_hop_id, RouteNextHop(old.first.ip_address.to_string()));
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
        route_set = [&](const sai_route_entry_t* entry, const sai_attribute_t* attr) {
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
            .WillRepeatedly([&](sai_object_id_t oid) {
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
                .WillOnce([](SET_BULK_ATTR_PARAMS(route)) {
                    EXPECT_EQ(3u, object_count);
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = i == 1 ? SAI_STATUS_FAILURE
                            : old_sai_route_api->set_route_entry_attribute(&route__entry[i], &attr_list[i]);
                    return SAI_STATUS_FAILURE;
                })
                .WillRepeatedly([](SET_BULK_ATTR_PARAMS(route)) {
                    return old_sai_route_api->set_route_entries_attribute(SET_BULK_ATTR_ARGS(route));
                });
        }
        else
        {
            EXPECT_CALL(*mock_sai_route_api, remove_route_entries)
                .WillOnce([](REMOVE_BULK_PARAMS(route)) {
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
            EXPECT_EQ(old.second, RouteNextHop(old.first.to_string()));
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
            .WillRepeatedly([&](GENERIC_CREATE_PARAMS(next_hop_group_member)) {
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
                .WillOnce([](GENERIC_BULK_REMOVE_PARAMS(next_hop)) {
                    auto result = old_sai_next_hop_api->remove_next_hops(GENERIC_BULK_REMOVE_ARGS(next_hop));
                    for (uint32_t i = 0; i < object_count; ++i)
                        EXPECT_EQ(SAI_STATUS_SUCCESS, object_statuses[i]);
                    return result;
                });
            EXPECT_CALL(*mock_sai_neighbor_api, remove_neighbor_entries)
                .WillOnce([](REMOVE_BULK_PARAMS(neighbor)) {
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = sai_serialize_ip_address(neighbor_entry[i].ip_address) == "a::a"
                            ? SAI_STATUS_FAILURE : old_sai_neighbor_api->remove_neighbor_entry(&neighbor_entry[i]);
                    return SAI_STATUS_FAILURE;
                });
        }
        else
        {
            EXPECT_CALL(*mock_sai_route_api, set_route_entries_attribute)
                .WillOnce([](SET_BULK_ATTR_PARAMS(route)) {
                    for (uint32_t i = 0; i < object_count; ++i)
                        object_statuses[i] = i == 0 ? SAI_STATUS_FAILURE
                            : old_sai_route_api->set_route_entry_attribute(&route__entry[i], &attr_list[i]);
                    return SAI_STATUS_FAILURE;
                })
                .WillRepeatedly([](SET_BULK_ATTR_PARAMS(route)) {
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
            ASSERT_TRUE(gNeighOrch->setNextHopFlag(Key(member.first.to_string()), NHFLAGS_IFDOWN));
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
            EXPECT_EQ(nh.second.ref_count - 1, gNeighOrch->getNextHopRefCount(nh.first));
    }

    INSTANTIATE_TEST_SUITE_P(HostAndPrefix, MuxTransitionModesTest,
                            testing::Values(string("host-route"), string("prefix-route")));

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
