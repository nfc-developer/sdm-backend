import argparse
import binascii

from flask import Flask, request, render_template, jsonify
from werkzeug.exceptions import BadRequest

from derive import derive_tag_key, derive_undiversified_key
from config import SDMMAC_PARAM, ENC_FILE_DATA_PARAM, ENC_PICC_DATA_PARAM, SDM_MASTER_KEY, UID_PARAM, CTR_PARAM, REQUIRE_LRP
from libsdm import decrypt_sun_message, validate_plain_sun, InvalidMessage, EncMode

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, msg=str(e)), 400


@app.errorhandler(403)
def bad_request(e):
    return render_template('error.html', code=403, msg=str(e)), 403


@app.errorhandler(404)
def bad_request(e):
    return render_template('error.html', code=404, msg=str(e)), 404


@app.context_processor
def inject_demo_mode():
    demo_mode = (SDM_MASTER_KEY == (b"\x00" * 16))
    return {"demo_mode": demo_mode}


@app.route('/')
def sdm_main():
    """
    Main page with a few examples.
    """
    return render_template('sdm_main.html')


def _internal_sdm(with_tt=False, force_json=False):
    """
    SUN decrypting/validating endpoint.
    """
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

    try:
        res = decrypt_sun_message(sdm_meta_read_key=derive_undiversified_key(SDM_MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(SDM_MASTER_KEY, uid, 2),
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

    if file_data:
        file_data_utf8 = file_data.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data_utf8[0]
            tt_cur_status = file_data_utf8[1]

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
                                 sdm_file_read_key=derive_tag_key(SDM_MASTER_KEY, uid, 2))
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
