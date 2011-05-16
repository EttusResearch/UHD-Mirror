//
// Copyright 2010 Ettus Research LLC
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

#include "md5.hpp"
#include <uhd/usrp/dboard_base.hpp>
#include <boost/cstdint.hpp>
#include <boost/foreach.hpp>
#include <boost/assign.hpp>
#include <algorithm>
#include <utility>
#include <vector>

#define EE_DB_ID_OFFSET         0x99 //1 byte
#define EE_SERIAL_MSB_OFFSET    0xBE //1 byte
#define EE_SERIAL_LSB_OFFSET    0xC7 //1 byte
#define EE_RANDOM_OFFSET        0xD3 //1 byte
#define EE_MD5SUM_OFFSET        0xA1 //16 bytes
#define EE_HOST_SECRET          "899bukESe2EmuspU"

static UHD_INLINE void validate_dboard_xx(
    uhd::usrp::dboard_iface::sptr db_iface,
    const uhd::usrp::dboard_id_t &db_id,
    const std::string &xx
){
    //a table of dboards that we should validate
    static const std::vector<std::pair<uhd::usrp::dboard_id_t, uhd::usrp::dboard_id_t> > ids = boost::assign::list_of
        (std::make_pair(uhd::usrp::dboard_id_t(0x54), uhd::usrp::dboard_id_t(0x55))) //SBX
        (std::make_pair(uhd::usrp::dboard_id_t(0x46), uhd::usrp::dboard_id_t::none())) //TVRX2
    ;

    //look for id matches in the table above
    bool found_match = false;
    for (size_t i = 0; i < ids.size(); i++){
        if (xx == "rx" and ids[i].first == db_id){
            found_match = true; break;
        }
        if (xx == "tx" and ids[i].first == db_id){
            found_match = true; break;
        }
    }
    if (not found_match) return;

    //read the eeprom and collect into byte vector to check
    const boost::uint8_t ee_addr = ((xx == "rx")? 0x55 : 0x54) | ((db_iface->get_special_props().mangle_i2c_addrs)? 0x02 : 0x00);
    uhd::byte_vector_t bytes(4);
    bytes[0] = db_iface->read_eeprom(ee_addr, EE_DB_ID_OFFSET, 1).at(0);
    bytes[1] = db_iface->read_eeprom(ee_addr, EE_SERIAL_MSB_OFFSET, 1).at(0);
    bytes[2] = db_iface->read_eeprom(ee_addr, EE_SERIAL_LSB_OFFSET, 1).at(0);
    bytes[3] = db_iface->read_eeprom(ee_addr, EE_RANDOM_OFFSET, 1).at(0);
    BOOST_FOREACH(boost::uint8_t c, std::string(EE_HOST_SECRET)) bytes.push_back(c);

    //read the md5sum from the eeprom
    const uhd::byte_vector_t md5sum_ee_bytes = db_iface->read_eeprom(ee_addr, EE_MD5SUM_OFFSET, 16);

    //md5sum the eeprom bytes
    MD5 md5sum_host_obj;
    md5sum_host_obj.update(&bytes.front(), bytes.size());
    md5sum_host_obj.finalize();
    const unsigned char *md5sum_host_bytes = md5sum_host_obj.raw_digest();

    //check for equality between host bytes and eeprom bytes
    if (not std::equal(md5sum_ee_bytes.begin(), md5sum_ee_bytes.end(), md5sum_host_bytes)){
        throw uhd::runtime_error("operation borked with code 11, contact support@ettus.com");
    }
}
