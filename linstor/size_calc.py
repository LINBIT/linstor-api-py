import locale
from collections import OrderedDict


class SizeCalc(object):

    """
    Methods for converting decimal and binary sizes of different magnitudes
    """

    _base_2 = 0x0200
    _base_10 = 0x0A00

    UNIT_B = 0 | _base_2
    UNIT_KiB = 10 | _base_2
    UNIT_MiB = 20 | _base_2
    UNIT_GiB = 30 | _base_2
    UNIT_TiB = 40 | _base_2
    UNIT_PiB = 50 | _base_2
    UNIT_EiB = 60 | _base_2
    UNIT_ZiB = 70 | _base_2
    UNIT_YiB = 80 | _base_2

    UNIT_kB = 3 | _base_10
    UNIT_MB = 6 | _base_10
    UNIT_GB = 9 | _base_10
    UNIT_TB = 12 | _base_10
    UNIT_PB = 15 | _base_10
    UNIT_EB = 18 | _base_10
    UNIT_ZB = 21 | _base_10
    UNIT_YB = 24 | _base_10

    """
    Unit keys are lower-case; functions using the lookup table should
    convert the unit name to lower-case to look it up in this table
    """
    UNITS_MAP = OrderedDict([(unit_str.lower(), (unit_str, unit)) for unit_str, unit in [
        ('K', UNIT_KiB),
        ('kB', UNIT_kB),
        ('KiB', UNIT_KiB),
        ('M', UNIT_MiB),
        ('MB', UNIT_MB),
        ('MiB', UNIT_MiB),
        ('G', UNIT_GiB),
        ('GB', UNIT_GB),
        ('GiB', UNIT_GiB),
        ('T', UNIT_TiB),
        ('TB', UNIT_TB),
        ('TiB', UNIT_TiB),
        ('P', UNIT_PiB),
        ('PB', UNIT_PB),
        ('PiB', UNIT_PiB),
    ]])

    UNITS_LIST_STR = ', '.join([unit_str for unit_str, _ in UNITS_MAP.values()])

    @classmethod
    def convert(cls, size, unit_in, unit_out):
        """
        Convert a size value into a different scale unit

        Convert a size value specified in the scale unit of unit_in to
        a size value given in the scale unit of unit_out
        (e.g. convert from decimal megabytes to binary gigabytes, ...)

        @param   size: numeric size value
        @param   unit_in: scale unit selector of the size parameter
        @param   unit_out: scale unit selector of the return value
        @return: size value converted to the scale unit of unit_out
                 truncated to an integer value
        """
        fac_in = ((unit_in & 0xffffff00) >> 8) ** (unit_in & 0xff)
        div_out = ((unit_out & 0xffffff00) >> 8) ** (unit_out & 0xff)
        return (size * fac_in // div_out)

    @classmethod
    def convert_round_up(cls, size, unit_in, unit_out):
        """
        Convert a size value into a different scale unit and round up

        Convert a size value specified in the scale unit of unit_in to
        a size value given in the scale unit of unit_out
        (e.g. convert from decimal megabytes to binary gigabytes, ...).
        The result is rounded up so that the returned value always specifies
        a size that is large enough to contain the size supplied to this
        function.
        (e.g., for 100 decimal Megabytes (MB), which equals 100 million bytes,
         returns 97,657 binary kilobytes (kiB), which equals 100 million
         plus 768 bytes and therefore is large enough to contain 100 megabytes)

        @param   size: numeric size value
        @param   unit_in: scale unit selector of the size parameter
        @param   unit_out: scale unit selector of the return value
        @return: size value converted to the scale unit of unit_out
        """
        fac_in = ((unit_in & 0xffffff00) >> 8) ** (unit_in & 0xff)
        div_out = ((unit_out & 0xffffff00) >> 8) ** (unit_out & 0xff)
        byte_sz = size * fac_in
        if byte_sz % div_out != 0:
            result = (byte_sz / div_out) + 1
        else:
            result = byte_sz / div_out
        return int(result)

    @classmethod
    def approximate_size_string(cls, size_kib):
        """
        Produce human readable size information as a string
        """
        units = [
            "KiB",
            "MiB",
            "GiB",
            "TiB",
            "PiB"
        ]
        max_index = len(units)

        index = 0
        counter = 1
        magnitude = 1 << 10
        while counter < max_index:
            if size_kib >= magnitude:
                index = counter
            else:
                break
            magnitude = magnitude << 10
            counter += 1
        magnitude = magnitude >> 10

        size_str = None
        if size_kib % magnitude != 0:
            size_unit = float(size_kib) / magnitude
            size_loc = locale.format('%3.2f', size_unit, grouping=True)
            size_str = "%s %s" % (size_loc, units[index])
        else:
            size_unit = size_kib / magnitude
            size_str = "%d %s" % (size_unit, units[index])

        return size_str
