import argparse
import binascii
import io

from flask import Flask, request, render_template, jsonify
from werkzeug.exceptions import BadRequest

import warn_old_config
from derive import derive_tag_key, derive_undiversified_key
from config import SDMMAC_PARAM, ENC_FILE_DATA_PARAM, ENC_PICC_DATA_PARAM, SYSTEM_MASTER_KEY, UID_PARAM, CTR_PARAM, REQUIRE_LRP
from libsdm import decrypt_sun_message, validate_plain_sun, InvalidMessage, EncMode, ParamMode

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


@app.errorhandler(400)
def handler_bad_request(e):
    return render_template('error.html', code=400, msg=str(e)), 400


@app.errorhandler(403)
def handler_forbidden(e):
    return render_template('error.html', code=403, msg=str(e)), 403


@app.errorhandler(404)
def handler_not_found(e):
    return render_template('error.html', code=404, msg=str(e)), 404


@app.context_processor
def inject_demo_mode():
    demo_mode = (SYSTEM_MASTER_KEY == (b"\x00" * 16))
    return {"demo_mode": demo_mode}


@app.route('/')
def sdm_main():
    """
    Main page with a few examples.
    """
    return render_template('sdm_main.html')


def parse_parameters():
    if request.args.get('e'):
        param_mode = ParamMode.BULK
        e = request.args.get('e')

        try:
            e_b = binascii.unhexlify(e)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.")

        e_buf = io.BytesIO(e_b)

        if (len(e_b) - 8) % 16 == 0:
            # using AES (16 byte PICCEncData)
            file_len = len(e_b) - 16 - 8
            enc_picc_data_b = e_buf.read(16)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        elif (len(e_b) - 8) % 16 == 8:
            # using LRP (24 byte PICCEncData)
            file_len = len(e_b) - 24 - 8
            enc_picc_data_b = e_buf.read(24)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        else:
            raise BadRequest("Incorrect length of the dynamic parameter.")
    else:
        param_mode = ParamMode.SEPARATED
        enc_picc_data = request.args.get(ENC_PICC_DATA_PARAM)
        enc_file_data = request.args.get(ENC_FILE_DATA_PARAM)
        sdmmac = request.args.get(SDMMAC_PARAM)

        if not enc_picc_data:
            raise BadRequest("Parameter {} is required".format(ENC_PICC_DATA_PARAM))

        if not sdmmac:
            raise BadRequest("Parameter {} is required".format(SDMMAC_PARAM))

        try:
            enc_file_data_b = None
            enc_picc_data_b = binascii.unhexlify(enc_picc_data)
            sdmmac_b = binascii.unhexlify(sdmmac)

            if enc_file_data:
                enc_file_data_b = binascii.unhexlify(enc_file_data)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.")

    return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b


def _internal_sdm(with_tt=False, force_json=False):
    """
    SUN decrypting/validating endpoint.
    """
    param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b = parse_parameters()

    try:
        res = decrypt_sun_message(param_mode=param_mode,
                                  sdm_meta_read_key=derive_undiversified_key(SYSTEM_MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(SYSTEM_MASTER_KEY, uid, 2),
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).")

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    picc_data_tag = res['picc_data_tag']
    uid = res['uid']
    read_ctr_num = res['read_ctr']
    file_data = res['file_data']
    encryption_mode = res['encryption_mode'].name

    file_data_utf8 = ""
    tt_status_api = ""
    tt_status = ""
    tt_color = ""

    if res['file_data']:
        if param_mode == ParamMode.BULK:
            file_data_len = file_data[2]
            file_data_unpacked = file_data[3:3 + file_data_len]
        else:
            file_data_unpacked = file_data

        file_data_utf8 = file_data_unpacked.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data[0:1].decode('ascii', 'replace')
            tt_cur_status = file_data[1:2].decode('ascii', 'replace')

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status_api = 'secure'
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status_api = 'tampered_closed'
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status_api = 'tampered_open'
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            elif tt_perm_status == 'I' and tt_cur_status == 'I':
                tt_status_api = 'not_initialized'
                tt_status = 'Not initialized'
                tt_color = 'orange'
            elif tt_perm_status == 'N' and tt_cur_status == 'T':
                tt_status_api = 'not_supported'
                tt_status = 'Not supported by the tag'
                tt_color = 'orange'
            else:
                tt_status_api = 'unknown'
                tt_status = 'Unknown'
                tt_color = 'orange'

    if request.args.get("output") == "json" or force_json:
        return jsonify({
            "uid": uid.hex().upper(),
            "file_data": file_data.hex() if file_data else None,
            "read_ctr": read_ctr_num,
            "tt_status": tt_status_api,
            "enc_mode": encryption_mode
        })
    else:
        return render_template('sdm_info.html',
                               encryption_mode=encryption_mode,
                               picc_data_tag=picc_data_tag,
                               uid=uid,
                               read_ctr_num=read_ctr_num,
                               file_data=file_data,
                               file_data_utf8=file_data_utf8,
                               tt_status=tt_status,
                               tt_color=tt_color)


@app.route('/tagtt')
def sdm_info_tt():
    return _internal_sdm(with_tt=True)


@app.route('/api/tagtt')
def sdm_api_info_tt():
    try:
        return _internal_sdm(with_tt=True, force_json=True)
    except BadRequest as e:
        return jsonify({"error": str(e)})


@app.route('/tag')
def sdm_info():
    return _internal_sdm(with_tt=False)


@app.route('/api/tag')
def sdm_api_info():
    try:
        return _internal_sdm(with_tt=False, force_json=True)
    except BadRequest as e:
        return jsonify({"error": str(e)})


def _internal_tagpt(force_json=False):
    try:
        uid = binascii.unhexlify(request.args[UID_PARAM])
        read_ctr = binascii.unhexlify(request.args[CTR_PARAM])
        cmac = binascii.unhexlify(request.args[SDMMAC_PARAM])
    except binascii.Error:
        raise BadRequest("Failed to decode parameters.")

    try:
        res = validate_plain_sun(uid=uid,
                                 read_ctr=read_ctr,
                                 sdmmac=cmac,
                                 sdm_file_read_key=derive_tag_key(SYSTEM_MASTER_KEY, uid, 2))
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).")

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    if request.args.get("output") == "json" or force_json:
        return jsonify({
            "uid": res['uid'].hex().upper(),
            "read_ctr": res['read_ctr'],
            "enc_mode": res['encryption_mode'].name
        })
    else:
        return render_template('sdm_info.html',
                               encryption_mode=res['encryption_mode'].name,
                               uid=res['uid'],
                               read_ctr_num=res['read_ctr'])


@app.route('/tagpt')
def sdm_info_plain():
    return _internal_tagpt()


@app.route('/api/tagpt')
def sdm_api_info_plain():
    try:
        return _internal_tagpt(force_json=True)
    except BadRequest as e:
        return jsonify({"error": str(e)}), 400


@app.route('/webnfc')
def sdm_webnfc():
    return render_template('sdm_webnfc.html')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?',
                        help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?',
                        help='port to listen on')

    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
