import argparse
import binascii

from flask import Flask, request, render_template, jsonify
from werkzeug.exceptions import BadRequest

from config import SDMMAC_PARAM, ENC_FILE_DATA_PARAM, ENC_PICC_DATA_PARAM, SDM_FILE_READ_KEY, SDM_META_READ_KEY, UID_PARAM, CTR_PARAM
from libsdm import decrypt_sun_message, validate_plain_sun, InvalidMessage

app = Flask(__name__)


@app.route('/')
def sdm_main():
    """
    Main page with a few examples.
    """
    return render_template('sdm_main.html')


def _internal_sdm(with_tt=False):
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
        res = decrypt_sun_message(sdm_meta_read_key=SDM_META_READ_KEY,
                                  sdm_file_read_key=SDM_FILE_READ_KEY,
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).")

    picc_data_tag, uid, read_ctr_num, file_data = res

    file_data_utf8 = ""
    tt_status = ""
    tt_color = ""

    if file_data:
        file_data_utf8 = file_data.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data_utf8[0]
            tt_cur_status = file_data_utf8[1]

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            else:
                tt_status = 'Unknown'
                tt_color = 'yellow'

    if request.args.get("output") == "json":
        return jsonify({
            "uid": uid.hex().upper(),
            "file_data": file_data_utf8,
            "read_ctr": read_ctr_num,
            "tt_status": tt_status
        })
    else:
        return render_template('sdm_info.html',
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


@app.route('/tag')
def sdm_info():
    return _internal_sdm(with_tt=False)


@app.route('/tagpt')
def sdm_info_plain():
    try:
        uid = binascii.unhexlify(request.args[UID_PARAM])
        read_ctr = binascii.unhexlify(request.args[CTR_PARAM])
        cmac = binascii.unhexlify(request.args[SDMMAC_PARAM])
    except binascii.Error:
        raise BadRequest("Failed to decode parameters.")

    try:
        uid, read_ctr_num = validate_plain_sun(uid=uid,
                                               read_ctr=read_ctr,
                                               sdmmac=cmac,
                                               sdm_file_read_key=SDM_FILE_READ_KEY)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).")


    if request.args.get("output") == "json":
        return jsonify({
            "uid": uid.hex().upper(),
            "read_ctr": read_ctr_num
        })
    else:
        return render_template('sdm_info.html',
                               uid=uid,
                               read_ctr_num=read_ctr_num)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?',
                        help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?',
                        help='port to listen on')

    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
