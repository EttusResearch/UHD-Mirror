//
// Copyright 2010-2011 Ettus Research LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#include "usrp2_impl.hpp"
#include "usrp2_regs.hpp"
#include "fw_common.h"
#include <uhd/utils/log.hpp>
#include <uhd/utils/msg.hpp>
#include <uhd/utils/safe_call.hpp>
#include <uhd/exception.hpp>
#include <uhd/usrp/gps_ctrl.hpp>
#include <uhd/usrp/misc_utils.hpp>
#include <uhd/usrp/dsp_utils.hpp>
#include <uhd/usrp/mboard_props.hpp>
#include <uhd/utils/byteswap.hpp>
#include <uhd/utils/algorithm.hpp>
#include <uhd/types/sensors.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/bind.hpp>

static const double mimo_clock_delay_usrp2_rev4 = 4.18e-9;
static const double mimo_clock_delay_usrp_n2xx = 3.55e-9;
static const size_t mimo_clock_sync_delay_cycles = 137;

using namespace uhd;
using namespace uhd::usrp;
using namespace uhd::transport;

/***********************************************************************
 * Helpers
 **********************************************************************/
static void init_xport(zero_copy_if::sptr xport){
    //Send a small data packet so the usrp2 knows the udp source port.
    //This setup must happen before further initialization occurs
    //or the async update packets will cause ICMP destination unreachable.
    static const boost::uint32_t data[2] = {
        uhd::htonx(boost::uint32_t(0 /* don't care seq num */)),
        uhd::htonx(boost::uint32_t(USRP2_INVALID_VRT_HEADER))
    };

    transport::managed_send_buffer::sptr send_buff = xport->get_send_buff();
    std::memcpy(send_buff->cast<void*>(), &data, sizeof(data));
    send_buff->commit(sizeof(data));
}

/***********************************************************************
 * Structors
 **********************************************************************/
usrp2_mboard_impl::usrp2_mboard_impl(
    const device_addr_t &device_addr,
    size_t index, usrp2_impl &device
):
    _index(index), _device(device),
    _iface(usrp2_iface::make(udp_simple::make_connected(
        device_addr["addr"], BOOST_STRINGIZE(USRP2_UDP_CTRL_PORT)
    )))
{

    //check the fpga compatibility number
    const boost::uint32_t fpga_compat_num = _iface->peek32(U2_REG_COMPAT_NUM_RB);
    if (fpga_compat_num != USRP2_FPGA_COMPAT_NUM){
        throw uhd::runtime_error(str(boost::format(
            "\nPlease update the firmware and FPGA images for your device.\n"
            "See the application notes for USRP2/N-Series for instructions.\n"
            "Expected FPGA compatibility number %d, but got %d:\n"
            "The FPGA build is not compatible with the host code build."
        ) % int(USRP2_FPGA_COMPAT_NUM) % fpga_compat_num));
    }

    //lock the device/motherboard to this process
    _iface->lock_device(true);

    //construct transports for dsp and async errors
    UHD_LOG << "Making transport for DSP0..." << std::endl;
    device.dsp_xports.push_back(udp_zero_copy::make(
        device_addr["addr"], BOOST_STRINGIZE(USRP2_UDP_DSP0_PORT), device_addr
    ));
    init_xport(device.dsp_xports.back());

    UHD_LOG << "Making transport for DSP1..." << std::endl;
    device.dsp_xports.push_back(udp_zero_copy::make(
        device_addr["addr"], BOOST_STRINGIZE(USRP2_UDP_DSP1_PORT), device_addr
    ));
    init_xport(device.dsp_xports.back());

    UHD_LOG << "Making transport for ERR0..." << std::endl;
    device.err_xports.push_back(udp_zero_copy::make(
        device_addr["addr"], BOOST_STRINGIZE(USRP2_UDP_ERR0_PORT), device_addr_t()
    ));
    init_xport(device.err_xports.back());

    //contruct the interfaces to mboard perifs
    _clock_ctrl = usrp2_clock_ctrl::make(_iface);
    _codec_ctrl = usrp2_codec_ctrl::make(_iface);
    if (_iface->mb_eeprom["gpsdo"] == "internal"){
        _gps_ctrl = gps_ctrl::make(
            _iface->get_gps_write_fn(),
            _iface->get_gps_read_fn());
    }

    //init the dsp stuff (before setting update packets)
    dsp_init();

    //setting the cycles per update (disabled by default)
    const double ups_per_sec = device_addr.cast<double>("ups_per_sec", 20);
    if (ups_per_sec > 0.0){
        const size_t cycles_per_up = size_t(_clock_ctrl->get_master_clock_rate()/ups_per_sec);
        _iface->poke32(U2_REG_TX_CTRL_CYCLES_PER_UP, U2_FLAG_TX_CTRL_UP_ENB | cycles_per_up);
    }

    //setting the packets per update (enabled by default)
    size_t send_frame_size = device.dsp_xports[0]->get_send_frame_size();
    const double ups_per_fifo = device_addr.cast<double>("ups_per_fifo", 8.0);
    if (ups_per_fifo > 0.0){
        const size_t packets_per_up = size_t(usrp2_impl::sram_bytes/ups_per_fifo/send_frame_size);
        _iface->poke32(U2_REG_TX_CTRL_PACKETS_PER_UP, U2_FLAG_TX_CTRL_UP_ENB | packets_per_up);
    }

    //initialize the clock configuration
    if (device_addr.has_key("mimo_mode")){
        if (device_addr["mimo_mode"] == "master"){
            _mimo_clocking_mode_is_master = true;
        }
        else if (device_addr["mimo_mode"] == "slave"){
            _mimo_clocking_mode_is_master = false;
        }
        else throw uhd::value_error(
            "mimo_mode must be set to master or slave"
        );
    }
    else {
        _mimo_clocking_mode_is_master = (_iface->peek32(U2_REG_STATUS) & (1 << 8)) != 0;
    }
    UHD_MSG(status) << boost::format("mboard%d is MIMO %s") % _index %
        (_mimo_clocking_mode_is_master?"master":"slave") << std::endl;

    //init the clock config
    _clock_config = clock_config_t::internal();
    update_clock_config();

    //init the codec before the dboard
    codec_init();

    //init the tx and rx dboards (do last)
    dboard_init();

    //set default subdev specs
    (*this)[MBOARD_PROP_RX_SUBDEV_SPEC] = subdev_spec_t();
    (*this)[MBOARD_PROP_TX_SUBDEV_SPEC] = subdev_spec_t();

    //------------------------------------------------------------------
    //This is a hack/fix for the lingering packet problem.
    stream_cmd_t stream_cmd(stream_cmd_t::STREAM_MODE_NUM_SAMPS_AND_DONE);
    for (size_t i = 0; i < NUM_RX_DSPS; i++){
        size_t index = device.dsp_xports.size() - NUM_RX_DSPS + i;
        stream_cmd.num_samps = 1;
        this->issue_ddc_stream_cmd(stream_cmd, i);
        device.dsp_xports.at(index)->get_recv_buff(0.01).get(); //recv with timeout for lingering
        device.dsp_xports.at(index)->get_recv_buff(0.01).get(); //recv with timeout for expected
        _iface->poke32(U2_REG_RX_CTRL_CLEAR(i), 1); //resets sequence
    }
    //------------------------------------------------------------------
}

usrp2_mboard_impl::~usrp2_mboard_impl(void){
    //Safely destruct all RAII objects in an mboard.
    //This prevents the mboard deconstructor from throwing,
    //which allows the device to be safely deconstructed.
    UHD_SAFE_CALL(_iface->poke32(U2_REG_TX_CTRL_CYCLES_PER_UP, 0);)
    UHD_SAFE_CALL(_iface->poke32(U2_REG_TX_CTRL_PACKETS_PER_UP, 0);)
    UHD_SAFE_CALL(_dboard_manager.reset();)
    UHD_SAFE_CALL(_dboard_iface.reset();)
    UHD_SAFE_CALL(_codec_ctrl.reset();)
    UHD_SAFE_CALL(_clock_ctrl.reset();)
    UHD_SAFE_CALL(_gps_ctrl.reset();)
}

/***********************************************************************
 * Helper Methods
 **********************************************************************/
void usrp2_mboard_impl::update_clock_config(void){
    boost::uint32_t pps_flags = 0;

    //slave mode overrides clock config settings
    if (not _mimo_clocking_mode_is_master){
        _clock_config.ref_source = clock_config_t::REF_MIMO;
        _clock_config.pps_source = clock_config_t::PPS_MIMO;
    }

    //translate pps source enums
    switch(_clock_config.pps_source){
    case clock_config_t::PPS_MIMO:
        _iface->poke32(U2_REG_TIME64_MIMO_SYNC,
            (1 << 8) | (mimo_clock_sync_delay_cycles & 0xff)
        );
        break;

    case clock_config_t::PPS_SMA:
        _iface->poke32(U2_REG_TIME64_MIMO_SYNC, 0);
        pps_flags |= U2_FLAG_TIME64_PPS_SMA;
        break;

    default: throw uhd::value_error("unhandled clock configuration pps source");
    }

    //translate pps polarity enums
    switch(_clock_config.pps_polarity){
    case clock_config_t::PPS_POS: pps_flags |= U2_FLAG_TIME64_PPS_POSEDGE; break;
    case clock_config_t::PPS_NEG: pps_flags |= U2_FLAG_TIME64_PPS_NEGEDGE; break;
    default: throw uhd::value_error("unhandled clock configuration pps polarity");
    }

    //set the pps flags
    _iface->poke32(U2_REG_TIME64_FLAGS, pps_flags);

    //clock source ref 10mhz
    switch(_iface->get_rev()){
    case usrp2_iface::USRP_N200:
    case usrp2_iface::USRP_N210:
    case usrp2_iface::USRP_N200_R4:
    case usrp2_iface::USRP_N210_R4:
        switch(_clock_config.ref_source){
        case clock_config_t::REF_INT : _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x12); break;
        case clock_config_t::REF_SMA : _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x1C); break;
        case clock_config_t::REF_MIMO: _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x15); break;
        default: throw uhd::value_error("unhandled clock configuration reference source");
        }
        _clock_ctrl->enable_external_ref(true); //USRP2P has an internal 10MHz TCXO
        break;

    case usrp2_iface::USRP2_REV3:
    case usrp2_iface::USRP2_REV4:
        switch(_clock_config.ref_source){
        case clock_config_t::REF_INT : _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x10); break;
        case clock_config_t::REF_SMA : _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x1C); break;
        case clock_config_t::REF_MIMO: _iface->poke32(U2_REG_MISC_CTRL_CLOCK, 0x15); break;
        default: throw uhd::value_error("unhandled clock configuration reference source");
        }
        _clock_ctrl->enable_external_ref(_clock_config.ref_source != clock_config_t::REF_INT);
        break;

    case usrp2_iface::USRP_NXXX: break;
    }

    //masters always drive the clock over serdes
    _clock_ctrl->enable_mimo_clock_out(_mimo_clocking_mode_is_master);

    //set the mimo clock delay over the serdes
    if (_mimo_clocking_mode_is_master){
        switch(_iface->get_rev()){
        case usrp2_iface::USRP_N200:
        case usrp2_iface::USRP_N210:
        case usrp2_iface::USRP_N200_R4:
        case usrp2_iface::USRP_N210_R4:
            _clock_ctrl->set_mimo_clock_delay(mimo_clock_delay_usrp_n2xx);
            break;

        case usrp2_iface::USRP2_REV4:
            _clock_ctrl->set_mimo_clock_delay(mimo_clock_delay_usrp2_rev4);
            break;

        default: break; //not handled
        }
    }

}

void usrp2_mboard_impl::set_time_spec(const time_spec_t &time_spec, bool now){
    //dont set the time for slave devices, they always take from mimo cable
    if (not _mimo_clocking_mode_is_master) return;

    //set the ticks
    _iface->poke32(U2_REG_TIME64_TICKS, time_spec.get_tick_count(get_master_clock_freq()));

    //set the flags register
    boost::uint32_t imm_flags = (now)? U2_FLAG_TIME64_LATCH_NOW : U2_FLAG_TIME64_LATCH_NEXT_PPS;
    _iface->poke32(U2_REG_TIME64_IMM, imm_flags);

    //set the seconds (latches in all 3 registers)
    _iface->poke32(U2_REG_TIME64_SECS, boost::uint32_t(time_spec.get_full_secs()));
}

/***********************************************************************
 * MBoard Get Properties
 **********************************************************************/
static const std::string dboard_name = "0";

void usrp2_mboard_impl::get(const wax::obj &key_, wax::obj &val){
    named_prop_t key = named_prop_t::extract(key_);
    //handle the get request conditioned on the key
    switch(key.as<mboard_prop_t>()){
    case MBOARD_PROP_NAME:
        val = _iface->get_cname() + " mboard";
        return;

    case MBOARD_PROP_OTHERS:
        val = prop_names_t();
        return;

    case MBOARD_PROP_RX_DBOARD:
        UHD_ASSERT_THROW(key.name == dboard_name);
        val = _rx_dboard_proxy->get_link();
        return;

    case MBOARD_PROP_RX_DBOARD_NAMES:
        val = prop_names_t(1, dboard_name);
        return;

    case MBOARD_PROP_TX_DBOARD:
        UHD_ASSERT_THROW(key.name == dboard_name);
        val = _tx_dboard_proxy->get_link();
        return;

    case MBOARD_PROP_TX_DBOARD_NAMES:
        val = prop_names_t(1, dboard_name);
        return;

    case MBOARD_PROP_RX_DSP:
        val = _rx_dsp_proxies[key.name]->get_link();
        return;

    case MBOARD_PROP_RX_DSP_NAMES:
        val = _rx_dsp_proxies.keys();
        return;

    case MBOARD_PROP_TX_DSP:
        val = _tx_dsp_proxies[key.name]->get_link();
        return;

    case MBOARD_PROP_TX_DSP_NAMES:
        val = _tx_dsp_proxies.keys();
        return;

    case MBOARD_PROP_CLOCK_CONFIG:
        val = _clock_config;
        return;

    case MBOARD_PROP_TIME_NOW: while(true){
        uint32_t secs = _iface->peek32(U2_REG_TIME64_SECS_RB_IMM);
        uint32_t ticks = _iface->peek32(U2_REG_TIME64_TICKS_RB_IMM);
        if (secs != _iface->peek32(U2_REG_TIME64_SECS_RB_IMM)) continue;
        val = time_spec_t(secs, ticks, get_master_clock_freq());
        return;
    }

    case MBOARD_PROP_TIME_PPS: while(true){
        uint32_t secs = _iface->peek32(U2_REG_TIME64_SECS_RB_PPS);
        uint32_t ticks = _iface->peek32(U2_REG_TIME64_TICKS_RB_PPS);
        if (secs != _iface->peek32(U2_REG_TIME64_SECS_RB_PPS)) continue;
        val = time_spec_t(secs, ticks, get_master_clock_freq());
        return;
    }

    case MBOARD_PROP_RX_SUBDEV_SPEC:
        val = _rx_subdev_spec;
        return;

    case MBOARD_PROP_TX_SUBDEV_SPEC:
        val = _tx_subdev_spec;
        return;

    case MBOARD_PROP_EEPROM_MAP:
        val = _iface->mb_eeprom;
        return;

    case MBOARD_PROP_CLOCK_RATE:
        val = this->get_master_clock_freq();
        return;

    case SUBDEV_PROP_SENSOR_NAMES:{
            prop_names_t names = boost::assign::list_of("mimo_locked")("ref_locked");
            if (_gps_ctrl.get()) names.push_back("gps_time");
            val = names;
        }
        return;

    case MBOARD_PROP_SENSOR:
        if(key.name == "mimo_locked") {
            val = sensor_value_t("MIMO", this->get_mimo_locked(), "locked", "unlocked");
            return;
        }
        else if(key.name == "ref_locked") {
            val = sensor_value_t("Ref", this->get_ref_locked(), "locked", "unlocked");
            return;
        }
        else if(key.name == "gps_time" and _gps_ctrl.get()) {
            val = sensor_value_t("GPS time", int(_gps_ctrl->get_epoch_time()), "seconds");
        }
        else {
            UHD_THROW_PROP_GET_ERROR();
        }
        break;

    default: UHD_THROW_PROP_GET_ERROR();
    }
}

bool usrp2_mboard_impl::get_mimo_locked(void) {
  return bool((_iface->peek32(U2_REG_IRQ_RB) & (1<<10)) > 0);
}

bool usrp2_mboard_impl::get_ref_locked(void) {
  return bool((_iface->peek32(U2_REG_IRQ_RB) & (1<<11)) > 0);
}

/***********************************************************************
 * MBoard Set Properties
 **********************************************************************/
void usrp2_mboard_impl::set(const wax::obj &key, const wax::obj &val){
    //handle the set request conditioned on the key
    switch(key.as<mboard_prop_t>()){

    case MBOARD_PROP_CLOCK_CONFIG:
        _clock_config = val.as<clock_config_t>();
        update_clock_config();
        return;

    case MBOARD_PROP_TIME_NOW:
        set_time_spec(val.as<time_spec_t>(), true);
        return;

    case MBOARD_PROP_TIME_PPS:
        set_time_spec(val.as<time_spec_t>(), false);
        return;

    case MBOARD_PROP_RX_SUBDEV_SPEC:
        _rx_subdev_spec = val.as<subdev_spec_t>();
        verify_rx_subdev_spec(_rx_subdev_spec, this->get_link());
        //sanity check
        UHD_ASSERT_THROW(_rx_subdev_spec.size() <= NUM_RX_DSPS);
        //set the mux
        for (size_t i = 0; i < _rx_subdev_spec.size(); i++){
            _iface->poke32(U2_REG_DSP_RX_MUX(i), dsp_type1::calc_rx_mux_word(
                _dboard_manager->get_rx_subdev(_rx_subdev_spec[i].sd_name)[SUBDEV_PROP_CONNECTION].as<subdev_conn_t>()
            ));
        }
        _device.update_xport_channel_mapping();
        return;

    case MBOARD_PROP_TX_SUBDEV_SPEC:
        _tx_subdev_spec = val.as<subdev_spec_t>();
        verify_tx_subdev_spec(_tx_subdev_spec, this->get_link());
        //sanity check
        UHD_ASSERT_THROW(_tx_subdev_spec.size() <= NUM_TX_DSPS);
        //set the mux
        for (size_t i = 0; i < _rx_subdev_spec.size(); i++){
            _iface->poke32(U2_REG_DSP_TX_MUX, dsp_type1::calc_tx_mux_word(
                _dboard_manager->get_tx_subdev(_tx_subdev_spec[i].sd_name)[SUBDEV_PROP_CONNECTION].as<subdev_conn_t>()
            ));
        }
        _device.update_xport_channel_mapping();
        return;

    case MBOARD_PROP_EEPROM_MAP:
        // Step1: commit the map, writing only those values set.
        // Step2: readback the entire eeprom map into the iface.
        val.as<mboard_eeprom_t>().commit(*_iface, mboard_eeprom_t::MAP_N100);
        _iface->mb_eeprom = mboard_eeprom_t(*_iface, mboard_eeprom_t::MAP_N100);
        return;

    case MBOARD_PROP_CLOCK_RATE:
        UHD_ASSERT_THROW(val.as<double>() == this->get_master_clock_freq());
        return;

    default: UHD_THROW_PROP_SET_ERROR();
    }
}
