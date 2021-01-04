"""
Copyright (c) 2020  Deltares - Michiel Tukker

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from virustotal import VirusTotalObject, get_sha256, upload_check_files, check_file_hashes
from settings import api_token

if __name__ == "__main__":
    print('Checking files with VirusTotal:')

    files_to_be_checked = [
        r'..\Data\Release\pumpchar.exe',
        r'..\Data\Release\syschar.exe',
        r'..\Data\Release\steady.exe',
        r'..\Data\Release\unsteady.exe',
        r'..\Data\Release\ua.exe',
        r'..\Data\Release\Wanda4.exe',
        r'..\Data\Release\WandaEngine_native.dll',
        r'..\Data\Release\PumpEnergy.dll',
        r'..\Data\Release\component.dll',
        r'..\Data\Release\RefPropDll.dll',
        r'..\Data\Release\WandaIgxExt46x.dll',
        r'..\Data\Wanda-4.6.0.msi',
    ]

    #    upload_check_files(files_to_be_checked, api_token)
    check_file_hashes(files_to_be_checked, api_token)
    print('Finished.')
