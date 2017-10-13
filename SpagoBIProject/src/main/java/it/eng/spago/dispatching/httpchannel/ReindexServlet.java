package it.eng.spago.dispatching.httpchannel;

import it.eng.spago.error.EMFUserError;
import it.eng.spagobi.analiticalmodel.document.bo.BIObject;
import it.eng.spagobi.analiticalmodel.document.dao.IBIObjectDAO;
import it.eng.spagobi.commons.dao.DAOFactory;
import it.eng.spagobi.commons.utilities.indexing.LuceneIndexer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;

public class ReindexServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/plain");
        try {
            IBIObjectDAO biObjectDAO = DAOFactory.getBIObjectDAO();
            List<BIObject> objects = biObjectDAO.loadAllBIObjects();
            for (BIObject biObject : objects) {
                LuceneIndexer.updateBiobjInIndex(biObject, false);
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.getOutputStream().println(objects.size() + " objects");
        } catch (EMFUserError emfUserError) {
            emfUserError.printStackTrace();
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            emfUserError.printStackTrace(new PrintStream(resp.getOutputStream()));
        }
    }
}
