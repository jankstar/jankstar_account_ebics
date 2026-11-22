# This file is part of the account_ebics module for Tryton.
# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from trytond.i18n import gettext
from trytond.model import DeactivableMixin, ModelSQL, ModelView, fields
from trytond.model.exceptions import ValidationError
from trytond.pyson import Eval
from trytond.transaction import Transaction

# Fields that identify a format (FO02); empty values count as equal.
KEY_FIELDS = ['direction', 'service_name', 'scope', 'service_option',
    'msg_name', 'msg_version', 'container']


class Format(DeactivableMixin, ModelSQL, ModelView):
    __name__ = 'account.ebics.format'
    __string__ = "EBICS Format"

    name = fields.Char("Name", required=True, translate=True)
    direction = fields.Selection([
            ('download', "Download"),
            ('upload', "Upload"),
            ], "Direction", required=True, sort=False)
    service_name = fields.Char(
        "Service Name", required=True,
        help="BTF service name, e.g. EOP, STM, SCT.")
    scope = fields.Char(
        "Scope",
        help="BTF scope, e.g. DE. Leave empty for global formats.")
    service_option = fields.Char(
        "Service Option", help="BTF service option, e.g. COR, VOO1.")
    msg_name = fields.Char(
        "Message Name", required=True,
        help="BTF message name, e.g. camt.053.")
    msg_version = fields.Char(
        "Message Version", help="Optional BTF message version, e.g. 08.")
    container = fields.Selection([
            (None, ""),
            ('ZIP', "ZIP"),
            ('XML', "XML"),
            ('SVC', "SVC"),
            ], "Container", sort=False)
    processing = fields.Selection([
            (None, ""),
            ('import_statement', "Import as Statement"),
            ('store', "Store Only"),
            ], "Processing", sort=False,
        states={
            'required': Eval('direction') == 'download',
            'invisible': Eval('direction') != 'download',
            },
        help="What happens with the downloaded files.")
    btf_params = fields.Function(
        fields.Char("BTF Parameters"), 'get_btf_params')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order.insert(0, ('name', 'ASC'))
        cls.active.help = (
            "Deactivate standard formats instead of deleting them.")

    @classmethod
    def default_direction(cls):
        return 'download'

    @staticmethod
    def build_btf_params(service_name, scope=None, service_option=None,
            msg_name=None, msg_version=None, container=None):
        "Return the BTF parameters as text, e.g. EOP/DE/camt.053/ZIP"
        parts = [service_name, scope, service_option, msg_name, msg_version,
            container]
        return '/'.join(p.strip() for p in parts if p and p.strip())

    @property
    def btf_text(self):
        return self.build_btf_params(
            self.service_name, self.scope, self.service_option,
            self.msg_name, self.msg_version, self.container)

    def get_btf_params(self, name):
        return self.btf_text

    def _key(self):
        return tuple(
            (getattr(self, f, None) or '').strip() for f in KEY_FIELDS)

    @classmethod
    def validate_fields(cls, formats, field_names):
        super().validate_fields(formats, field_names)
        cls.check_processing(formats, field_names)

    @classmethod
    def check_processing(cls, formats, field_names=None):
        if field_names and not (
                field_names & {'direction', 'processing', 'msg_name'}):
            return
        for format_ in formats:
            # FO01
            if format_.direction == 'download' and not format_.processing:
                raise ValidationError(gettext(
                        'account_ebics.msg_format_processing_required',
                        format=format_.rec_name))
            if format_.direction != 'download' and format_.processing:
                raise ValidationError(gettext(
                        'account_ebics.msg_format_processing_download',
                        format=format_.rec_name))
            # FO03
            if (format_.processing == 'import_statement'
                    and (format_.msg_name or '').strip() != 'camt.053'):
                raise ValidationError(gettext(
                        'account_ebics.msg_format_import_camt053',
                        format=format_.rec_name))

    @classmethod
    def validate(cls, formats):
        super().validate(formats)
        cls.check_unique(formats)

    @classmethod
    def check_unique(cls, formats):
        # FO02: SQL unique constraints do not cover empty (NULL) values
        keys = {}
        with Transaction().set_context(active_test=False):
            all_formats = cls.search([])
        for format_ in all_formats:
            keys.setdefault(format_._key(), []).append(format_.id)
        for format_ in formats:
            if len(keys.get(format_._key(), [])) > 1:
                raise ValidationError(gettext(
                        'account_ebics.msg_format_unique',
                        format=format_.rec_name,
                        btf=format_.btf_text))
