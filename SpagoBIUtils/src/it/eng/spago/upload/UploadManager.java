/**

SpagoBI - The Business Intelligence Free Platform

Copyright (C) 2005-2008 Engineering Ingegneria Informatica S.p.A.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

**/
package it.eng.spago.upload;

import it.eng.spago.base.SourceBean;
import it.eng.spago.dispatching.httpchannel.upload.IUploadHandler;
import it.eng.spago.dispatching.service.DefaultRequestContext;

import org.apache.commons.fileupload.FileItem;

public class UploadManager extends DefaultRequestContext implements IUploadHandler {

	/* (non-Javadoc)
	 * @see it.eng.spago.dispatching.httpchannel.upload.IUploadHandler#upload(org.apache.commons.fileupload.FileItem)
	 */
	public void upload(FileItem item) throws Exception {
		if (item != null) {
			SourceBean serviceRequest = getServiceRequest();
			serviceRequest.setAttribute("UPLOADED_FILE", item);
		}
		
//		long size = item.getSize();
//		
//		if(size>0) {
//			UploadedFile uploadedFile = new UploadedFile();
//			uploadedFile.setFileContent(item.get());
//			uploadedFile.setFieldNameInForm(item.getFieldName());
//			uploadedFile.setSizeInBytes(item.getSize());
//			uploadedFile.setFileName(GeneralUtilities.getRelativeFileNames(item.getName()));
//			SourceBean serviceRequest = getServiceRequest();
//			serviceRequest.setAttribute("UPLOADED_FILE", uploadedFile);
//		}
	}

}
